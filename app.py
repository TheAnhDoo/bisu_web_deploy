from flask import Flask, request, render_template, jsonify, send_file, session, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from web3 import Web3, HTTPProvider
import pandas as pd
import os
import sqlite3
import logging
from eth_account import Account
from mnemonic import Mnemonic
from werkzeug.security import generate_password_hash, check_password_hash
from threading import Lock
from flask import g  # Import `g` for thread-safe DB connections

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
#app.config['DATABASE'] = 'wallets.db'
app.config['DATABASE'] = '/data/wallets.db'  # Use Railway's persistent storage

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Web3 setup
SEPOLIA_RPCS = ["https://eth-sepolia.public.blastapi.io", "https://rpc.sepolia.org"]
MONAD_RPCS = ["https://sepolia-rpc.monad.xyz"]
sepolia_web3 = Web3(HTTPProvider(SEPOLIA_RPCS[0]))
db_lock = Lock()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['role'])
    return None

# Database setup
import os

def init_db():
    os.makedirs("/data", exist_ok=True)  # Ensure /data exists
    conn = sqlite3.connect(app.config['DATABASE'])
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mnemonic TEXT NOT NULL,
        address TEXT NOT NULL,
        private_key TEXT NOT NULL,
        group_name TEXT,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE (group_name, user_id) ON CONFLICT IGNORE
    )''')
    # Create admin user if not exists
    admin_exists = c.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin_exists:
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ('admin', generate_password_hash('admin123'), 'admin'))
    conn.commit()
    conn.close()


def get_db_connection():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], check_same_thread=False)
        g.db.row_factory = sqlite3.Row  # Return results as dicts
    return g.db

@app.teardown_appcontext
def close_db_connection(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# Migrate Excel data to SQLite (for admin only)
def migrate_excel_to_db():
    if os.path.exists("/data/wallets.xlsx"):

        conn = get_db_connection()
        df = pd.read_excel("wallets.xlsx")
        admin_id = conn.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()['id']
        for _, row in df.iterrows():
            conn.execute("INSERT INTO wallets (mnemonic, address, private_key, group_name, user_id) VALUES (?, ?, ?, ?, ?)",
                         (row["Mnemonic"], row["Address"], row["Private Key"], "default", admin_id))
        conn.commit()
        conn.close()
        logger.info("Migrated wallets.xlsx to database for admin")
        os.rename("wallets.xlsx", "wallets.xlsx.bak")

# Wallet creation function
def create_wallet():
    Account.enable_unaudited_hdwallet_features()
    mnemo = Mnemonic("english")
    mnemonic_phrase = mnemo.generate(strength=256)
    acct = Account.from_mnemonic(mnemonic_phrase)
    return {"mnemonic": mnemonic_phrase, "address": acct.address, "private_key": acct.key.hex(), "group_name": None}  # Explicitly None

# Routes
@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            login_user(User(user['id'], user['username'], user['role']))
            return redirect(url_for('home'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                         (username, generate_password_hash(password)))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/create_wallets_page')
@login_required
def create_wallets_page():
    return render_template("create_wallets.html")

@app.route('/create_wallets', methods=['POST'])
@login_required
def create_wallets():
    try:
        num = int(request.form.get("num_wallets"))
        if num < 1 or num > 100:
            return jsonify({"error": "Number must be between 1 and 100"}), 400
        
        new_wallets = [create_wallet() for _ in range(num)]
        with db_lock:
            conn = get_db_connection()
            for wallet in new_wallets:
                conn.execute("INSERT INTO wallets (mnemonic, address, private_key, group_name, user_id) VALUES (?, ?, ?, ?, ?)",
                             (wallet["mnemonic"], wallet["address"], wallet["private_key"], wallet["group_name"], current_user.id))
            conn.commit()
            conn.close()
        return jsonify({"message": f"Created {num} wallets successfully", "new_wallets": new_wallets})
    except Exception as e:
        logger.error(f"Error in create_wallets: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
@app.route('/divide_funds_page')
@login_required
def divide_funds_page():
    return render_template("divide_funds.html")

@app.route('/divide_funds', methods=['POST'])
@login_required
def divide_funds():
    try:
        data = request.json
        private_key = data.get("private_key")
        amount = Web3.to_wei(float(data.get("amount")), "ether")
        wallets = data.get("wallets", [])
        manual_wallets = data.get("manual_wallets", [])

        sender_account = Account.from_key(private_key)
        sender_address = sender_account.address
        all_wallets = wallets + manual_wallets

        balance = sepolia_web3.eth.get_balance(sender_address)
        if balance < amount * len(all_wallets):
            return jsonify({"error": "Insufficient balance"}), 400

        gas_price = sepolia_web3.eth.gas_price
        results = []
        for wallet in all_wallets:
            nonce = sepolia_web3.eth.get_transaction_count(sender_address, 'pending')
            tx = {
                "from": sender_address,
                "to": wallet,
                "value": amount,
                "gas": 21000,
                "gasPrice": gas_price,
                "nonce": nonce,
                "chainId": 11155111
            }
            signed_tx = sepolia_web3.eth.account.sign_transaction(tx, private_key)
            tx_hash = sepolia_web3.eth.send_raw_transaction(signed_tx.raw_transaction)
            results.append(f"Sent {data.get('amount')} ETH to {wallet}, TX: {tx_hash.hex()}")
        return jsonify({"message": results})
    except Exception as e:
        logger.error(f"Error in divide_funds: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/get_wallets')
@login_required
def get_wallets():
    conn = get_db_connection()
    wallets = conn.execute('SELECT address, group_name FROM wallets WHERE user_id = ?', (current_user.id,)).fetchall()
    result = []
    for wallet in wallets:
        balance = Web3.from_wei(sepolia_web3.eth.get_balance(wallet['address']), "ether") if sepolia_web3.is_connected() else "N/A"
        result.append({"address": wallet['address'], "group_name": wallet['group_name'], "eth_balance": balance})
    conn.close()
    return jsonify(result)

@app.route('/check_wallets_page')
@login_required
def check_wallets_page():
    return render_template("check_wallets.html")

@app.route('/check_balances')
@login_required
def check_balances():
    conn = get_db_connection()
    wallets = conn.execute('SELECT * FROM wallets WHERE user_id = ?', (current_user.id,)).fetchall()
    result = []
    for wallet in wallets:
        eth_balance = Web3.from_wei(sepolia_web3.eth.get_balance(wallet['address']), "ether") if sepolia_web3.is_connected() else "N/A"
        mon_balance = "N/A"  # Monad RPC not working reliably
        result.append({
            "Address": wallet['address'],
            "ETH Balance": eth_balance,
            "MON Balance": mon_balance,
            "Group": wallet['group_name']
        })
    conn.close()
    return jsonify(result)

@app.route('/import_wallets_page')
@login_required
def import_wallets_page():
    return render_template("import_wallets.html")

@app.route('/import_wallets/upload', methods=['POST'])
@login_required
def import_wallets_upload():
    logger.info("Received upload request")
    if 'walletFile' not in request.files:
        logger.error("No file uploaded")
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['walletFile']
    logger.info(f"Received file: {file.filename}")
    if not file.filename.endswith(('.xlsx', '.xls')):
        logger.error("Invalid file format")
        return jsonify({"error": "Invalid file format"}), 400
    try:
        df = pd.read_excel(file)
        logger.info(f"Excel file contents: {df.to_dict(orient='records')}")
        required_columns = {"Mnemonic", "Address", "Private Key"}
        if not required_columns.issubset(df.columns):
            logger.error("Missing required columns")
            return jsonify({"error": "Excel file must contain Mnemonic, Address, and Private Key columns"}), 400
        with db_lock:
            conn = get_db_connection()
            for _, row in df.iterrows():
                conn.execute("INSERT INTO wallets (mnemonic, address, private_key, group_name, user_id) VALUES (?, ?, ?, ?, ?)",
                             (row["Mnemonic"], row["Address"], row["Private Key"], None, current_user.id))
            conn.commit()
            conn.close()
            logger.info(f"Imported {len(df)} wallets for user {current_user.id}")
        return jsonify({"message": f"Successfully imported {len(df)} wallets"})
    except Exception as e:
        logger.error(f"Error in import_wallets_upload: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/import_wallets/manual', methods=['POST'])
@login_required
def import_wallets_manual():
    logger.info("Received manual import request")
    data = request.get_json()
    logger.info(f"Received data: {data}")
    mnemonic = data.get("mnemonic")
    address = data.get("address")
    private_key = data.get("privateKey")
    if not all([mnemonic, address, private_key]):
        logger.error("Missing required fields")
        return jsonify({"error": "All fields are required"}), 400
    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute("INSERT INTO wallets (mnemonic, address, private_key, group_name, user_id) VALUES (?, ?, ?, ?, ?)",
                         (mnemonic, address, private_key, None, current_user.id))
            conn.commit()
            conn.close()
            logger.info(f"Manually imported wallet for user {current_user.id}")
        return jsonify({"message": "Wallet added successfully"})
    except Exception as e:
        logger.error(f"Error in import_wallets_manual: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/dashboard')
@login_required
def dashboard_page():
    conn = get_db_connection()
    if current_user.role == 'admin':
        users = conn.execute('SELECT id, username, role FROM users').fetchall()
        wallets = conn.execute('SELECT w.id, w.mnemonic, w.address, w.private_key, w.group_name, w.user_id, u.username FROM wallets w JOIN users u ON w.user_id = u.id').fetchall()
        page_title = "Admin Dashboard"
    else:
        users = conn.execute('SELECT id, username, role FROM users WHERE id = ?', (current_user.id,)).fetchall()
        wallets = conn.execute('SELECT id, mnemonic, address, private_key, group_name, user_id FROM wallets WHERE user_id = ?', (current_user.id,)).fetchall()
        page_title = f"{current_user.username}'s Dashboard"
    conn.close()
    return render_template("dashboard.html", users=users, wallets=wallets, is_admin=(current_user.role == 'admin'), page_title=page_title)

@app.route('/dashboard/update_password', methods=['POST'])
@login_required
def dashboard_update_password():
    data = request.json
    user_id = data.get("user_id")
    new_password = data.get("new_password")
    
    if not new_password:
        return jsonify({"error": "New password is required"}), 400
        
    try:
        with db_lock:
            conn = get_db_connection()
            if current_user.role == 'admin':
                # Admin can update any user's password
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                            (generate_password_hash(new_password), user_id))
            else:
                # Regular user can only update their own password
                if int(user_id) != current_user.id:
                    conn.close()
                    return jsonify({"error": "Unauthorized: You can only change your own password"}), 403
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                            (generate_password_hash(new_password), current_user.id))
            conn.commit()
            conn.close()
        return jsonify({"message": "Password updated successfully"})
    except Exception as e:
        logger.error(f"Error in update_password: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/admin/delete_user', methods=['POST'])
@login_required
def admin_delete_user():
    if current_user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    user_id = request.json.get("user_id")
    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute("DELETE FROM wallets WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ? AND role != 'admin'", (user_id,))
            conn.commit()
            conn.close()
        return jsonify({"message": "User and their wallets deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/admin/delete_wallet', methods=['POST'])
@login_required
def admin_delete_wallet():
    if current_user.role != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
    wallet_id = request.json.get("wallet_id")
    try:
        with db_lock:
            conn = get_db_connection()
            conn.execute("DELETE FROM wallets WHERE id = ?", (wallet_id,))
            conn.commit()
            conn.close()
        return jsonify({"message": "Wallet deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/wallets')
@login_required
def wallets_page():
    conn = get_db_connection()
    wallets = conn.execute('SELECT id, mnemonic, address, private_key, group_name, user_id, (SELECT username FROM users WHERE users.id = wallets.user_id) as username FROM wallets WHERE user_id = ?', (current_user.id,)).fetchall()
    groups = conn.execute('SELECT DISTINCT group_name FROM wallets WHERE user_id = ? AND group_name IS NOT NULL', (current_user.id,)).fetchall()
    conn.close()
    
    # Convert Row objects to dictionaries
    wallets_dict = [dict(wallet) for wallet in wallets]
    groups_dict = [dict(group)['group_name'] for group in groups if dict(group)['group_name']]
    
    return render_template("wallets.html", wallets=wallets_dict, groups=groups_dict)

@app.route('/delete_wallet', methods=['POST'])
@login_required
def delete_wallet():
    try:
        data = request.get_json()
        wallet_id = data.get('wallet_id')
        if not wallet_id:
            return jsonify({"error": "Wallet ID is required"}), 400
        
        with db_lock:
            conn = get_db_connection()
            conn.execute("DELETE FROM wallets WHERE id = ? AND user_id = ?", (wallet_id, current_user.id))
            conn.commit()
            conn.close()
        return jsonify({"message": "Wallet deleted successfully"})
    except Exception as e:
        logger.error(f"Error in delete_wallet: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/delete_wallets', methods=['POST'])
@login_required
def delete_wallets():
    try:
        data = request.get_json()
        wallet_ids = data.get('wallet_ids')
        if not wallet_ids or not isinstance(wallet_ids, list):
            return jsonify({"error": "Wallet IDs list is required"}), 400
        
        with db_lock:
            conn = get_db_connection()
            conn.executemany("DELETE FROM wallets WHERE id = ? AND user_id = ?", [(id, current_user.id) for id in wallet_ids])
            conn.commit()
            conn.close()
        return jsonify({"message": f"Deleted {len(wallet_ids)} wallets successfully"})
    except Exception as e:
        logger.error(f"Error in delete_wallets: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/group_management')
@login_required
def group_management_page():
    conn = get_db_connection()
    if not current_user or not current_user.is_authenticated or not hasattr(current_user, "id") or current_user.id is None:
        conn.close()
        return redirect(url_for('login'))  # Redirect if user is not authenticated
    users = conn.execute('SELECT id, username FROM users').fetchall()
    wallets = conn.execute('SELECT id, address, group_name FROM wallets WHERE user_id = ?', (current_user.id,)).fetchall()
    conn.close()
    
    # Convert Row objects to dictionaries and remove any 'default' group
    wallets_dict = []
    for index, wallet in enumerate(wallets):
        wallet_dict = dict(wallet)
        if wallet_dict['group_name'] != 'default':
            # Fetch ETH balance using Web3 (similar to /get_wallets)
            try:
                eth_balance = Web3.from_wei(sepolia_web3.eth.get_balance(wallet_dict['address']), "ether") if sepolia_web3.is_connected() else "N/A"
                wallet_dict['eth_balance'] = eth_balance
            except Exception as e:
                logger.error(f"Error fetching ETH balance for address {wallet_dict['address']}: {str(e)}")
                wallet_dict['eth_balance'] = "N/A"
            wallets_dict.append(wallet_dict)
    users_dict = [dict(user) for user in users]
    
    # Fetch unique groups for the modal with error handling
    conn = get_db_connection()
    try:
        groups = conn.execute('SELECT DISTINCT group_name FROM wallets WHERE user_id = ? AND group_name IS NOT NULL', (current_user.id,)).fetchall()
        groups_dict = [dict(group)['group_name'] for group in groups if dict(group)['group_name']]
    except Exception as e:
        logger.error(f"Error fetching groups: {str(e)}")
        groups_dict = []
    finally:
        conn.close()
    
    return render_template("group_management.html", users=users_dict, wallets=wallets_dict, groups=groups_dict)

@app.route('/update_group', methods=['POST'])
@login_required
def update_group():
    data = request.json
    action = data.get("action")
    try:
        with db_lock:
            conn = get_db_connection()
            if action == "delete_group":
                group_name = data.get("group_name")
                if group_name:
                    conn.execute("UPDATE wallets SET group_name = NULL WHERE group_name = ? AND user_id = ?", (group_name, current_user.id))
                    conn.commit()
                    return jsonify({"message": f"Group '{group_name}' erased"})
                return jsonify({"error": "Group name is required"}), 400
            elif action == "assign_group":
                wallet_ids = data.get("wallet_ids")
                group_name = data.get("group_name")
                if wallet_ids and isinstance(wallet_ids, list):
                    conn.executemany("UPDATE wallets SET group_name = ? WHERE id = ? AND user_id = ?", [(group_name if group_name else None, wallet_id, current_user.id) for wallet_id in wallet_ids])
                    conn.commit()
                    return jsonify({"message": f"Assigned {len(wallet_ids)} wallets to '{group_name}'"})
                return jsonify({"error": "No valid wallet IDs provided"}), 400
            elif action == "create_group":
                group_name = data.get("group_name")
                if group_name:
                    # Check if group already exists for this user
                    if not conn.execute("SELECT 1 FROM wallets WHERE group_name = ? AND user_id = ?", (group_name, current_user.id)).fetchone():
                        # Insert a dummy wallet to register the group
                        conn.execute("INSERT INTO wallets (mnemonic, address, private_key, group_name, user_id) VALUES (?, ?, ?, ?, ?)",
                                     ("dummy", "0x0000000000000000000000000000000000000000", "dummy", group_name, current_user.id))
                        # Immediately delete the dummy wallet
                        conn.execute("DELETE FROM wallets WHERE mnemonic = 'dummy' AND address = '0x0000000000000000000000000000000000000000' AND user_id = ?", (current_user.id,))
                        conn.commit()
                        return jsonify({"message": f"Vault '{group_name}' created successfully"})
                    else:
                        return jsonify({"error": "Vault already exists"}), 400
                return jsonify({"error": "Group name is required"}), 400
            return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        logger.error(f"Error in update_group: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    migrate_excel_to_db()
    #app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
    app.run(debug=False, host='0.0.0.0', port=8080, threaded=True)
