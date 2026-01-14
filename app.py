from flask import Flask, request,render_template, redirect,session,Response,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from model import db,User
import bcrypt
import joblib
import numpy as np
import pandas as pd
import os
import sklearn
from threading import Thread
global filename
import matplotlib
matplotlib.use('Agg')   # Prevent GUI backend issue
import realtime_detector
import io
import base64
import matplotlib.pyplot as plt
from pathlib import Path
import re


filename=""


app = Flask(__name__)

#load the model
# model = joblib.load('model/StackingEnsemble.joblib')
#configure your database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Bind the SQLAlchemy object to your Flask app
db.init_app(app)
app.secret_key = 'secret_key'

# from youtube tutorial
app.config['SESSION_TYPE'] = 'filesystem'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# @app.route('/predict', methods=['GET', 'POST'])
# def packet_form():
#     result = None
#     if request.method == 'POST':
#         try:
#             # Collect form inputs in order
#             input_data = []
#             for feature in FEATURES:
#                 value = request.form.get(feature)
#                 if value is None or value.strip() == '':
#                     return render_template('form.html', result=f"Error: {feature} is required.")
#                 input_data.append(float(value))
            
#             # Convert to numpy array and reshape for prediction
#             input_array = np.array(input_data).reshape(1, -1)
            
#             # Predict using the stacking model
#             prediction = model.predict(input_array)[0]
            
#             # If it's classification, you can map numeric to labels
#             result = f"Predicted Value: {prediction}"
        
#         except ValueError:
#             result = "Invalid input! Please enter numeric values only."
#         except Exception as e:
#             result = f"Error: {str(e)}"

#     return render_template('dashboard.html', result=result)

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     email = db.Column(db.String(100), unique=True)
#     password = db.Column(db.String(100))

#     def __init__(self,email,password,name):
#         self.name = name
#         self.email = email
#         self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
#     def check_password(self,password):
#         return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

BASE_DIR = Path(__file__).parent
LOG_FILE = realtime_detector.LOG_FILE  # path to realtime.csv
# Optional: set label column constant
LABEL_COL = "label"
with app.app_context():
    # db.drop_all()
    db.create_all()
@app.context_processor
def inject_user():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return dict(user=user)
    return dict(user=None)


@app.route('/')
def home():
    return render_template('home.html')



def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# @app.route('/register', methods=['GET','POST'])
# def register():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']
#         confirm_password = request.form.get('confirm_password')

#         # Validate
#         if not name or not email or not password:
#             flash("Please fill in all fields", "error")
#             return redirect('/register')

#         if password != confirm_password:
#             flash("Passwords do not match", "error")
#             return redirect('/register')

#         # Check if user exists
#         existing_user = User.query.filter_by(email=email).first()
#         if existing_user:
#             flash("Email already registered. Please login.", "error")
#             return redirect('/register')

#         # Create new user with hashed password
#         new_user = User(name=name, email=email)
#         new_user.set_password(password)

#         db.session.add(new_user)
#         db.session.commit()

#         flash("Registration successful! Please login.")
#         return redirect('/login')

#     return render_template('register.html')
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # Basic validation
        if not name or not email or not password or not confirm_password:
            flash("Please fill in all fields", "danger")
            return redirect('/register')

        # Password match
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect('/register')

        # Strong password validation
        if not is_strong_password(password):
            flash(
                "Password must be at least 8 characters long and include "
                "uppercase, lowercase, number, and special character.",
                "danger"
            )
            return redirect('/register')

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.", "warning")
            return redirect('/register')

        # Create new user
        new_user = User(name=name, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template('register.html')

# @app.route('/login', methods=['GET','POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']

#         user = User.query.filter_by(email=email).first()

#         if user and user.check_password(password):
#             session['email'] = user.email
#             flash("Login successful!",'success')
#             return redirect('/dashboard')
#         else:
#             flash("Invalid email or password", "danger")
#             return redirect('/login')

#     return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid email or password", "danger")
            return redirect('/login')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    global cumulative_predictions
    user = User.query.filter_by(email=session['email']).first()
    
    
    if not cumulative_predictions:
        return render_template('dashboard.html',
                               user=user,
                               total_predictions=0,
                               attack_count=0,
                               normal_count=0,
                               accuracy=0,
                               attack_counts={},
                               plot_url_bar=None,
                               plot_url_pie=None,
                               plot_url_line=None)

    # Convert cumulative predictions into DataFrame
    df = pd.DataFrame(cumulative_predictions)

    # --- Metrics ---
    total_predictions = len(df)
    normal_count = (df['class_name'] == 'BENIGN').sum()
    attack_count = total_predictions - normal_count

    # --- Real Accuracy (if you have true labels, replace here) ---
    # For now, we calculate "model certainty" as % of BENIGN predictions
    accuracy = (normal_count / total_predictions) * 100 if total_predictions > 0 else 0

    # --- Class Distribution ---
    class_counts = df['class_name'].value_counts()
    # Ensure BENIGN first
    if 'BENIGN' in class_counts:
        class_counts = class_counts.reindex(['BENIGN'] + [c for c in class_counts.index if c != 'BENIGN'], fill_value=0)

    # =========================================
    # 1️⃣ Bar Chart — Class Distribution
    # =========================================
    plt.figure(figsize=(6, 4))
    class_counts.plot(kind='bar',
                      color=['#34d399' if c == 'BENIGN' else '#f87171' for c in class_counts.index])
    # plt.title("Cumulative Prediction Distribution")
    plt.xlabel("Class Name")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()

    img_bar = io.BytesIO()
    plt.savefig(img_bar, format='png')
    img_bar.seek(0)
    plot_url_bar = base64.b64encode(img_bar.getvalue()).decode()
    plt.close()

    # =========================================
    # 2️⃣ Pie Chart — Normal vs Attack Ratio
    # =========================================
    plt.figure(figsize=(5, 5))
    labels = ['BENIGN', 'ATTACK']
    sizes = [normal_count, attack_count]
    colors = ['#34d399', '#f87171']
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    # plt.title("Normal vs Attack Distribution")
    plt.tight_layout()

    img_pie = io.BytesIO()
    plt.savefig(img_pie, format='png')
    img_pie.seek(0)
    plot_url_pie = base64.b64encode(img_pie.getvalue()).decode()
    plt.close()

    # =========================================
    # 3️⃣ Line Chart — Cumulative BENIGN vs ATTACK
    # =========================================
    df['benign_cum'] = (df['class_name'] == 'BENIGN').cumsum()
    df['attack_cum'] = (df['class_name'] != 'BENIGN').cumsum()
    df['index'] = range(1, len(df) + 1)  # Use index as X-axis (like time)

    plt.figure(figsize=(7, 4))
    plt.plot(df['index'], df['benign_cum'], label='BENIGN', color='#10b981', linewidth=2)
    plt.plot(df['index'], df['attack_cum'], label='ATTACK', color='#ef4444', linewidth=2)
    # plt.title("Cumulative BENIGN vs ATTACK Over Time")
    plt.xlabel("Prediction Index")
    plt.ylabel("Cumulative Count")
    plt.legend()
    plt.xticks(rotation=30)
    plt.tight_layout()

    img_line = io.BytesIO()
    plt.savefig(img_line, format='png')
    img_line.seek(0)
    plot_url_line = base64.b64encode(img_line.getvalue()).decode()
    plt.close()

    # --- Chart.js or HTML use ---
    attack_counts = class_counts.to_dict()

    return render_template('dashboard.html',
                           total_predictions=total_predictions,
                           attack_count=attack_count,
                           normal_count=normal_count,
                           accuracy=round(accuracy, 2),
                           attack_counts=attack_counts,
                           plot_url_bar=plot_url_bar,
                           plot_url_pie=plot_url_pie,
                           plot_url_line=plot_url_line)

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')
# Load the trained model
model_filename='model/StackingEnsemble.joblib'
loaded_model = joblib.load(model_filename)

# print(loaded_model.feature_names_in_)
#Reverse mapping dictionary to decode predicted class
class_mapping_reverse={
    0:'BENIGN',
    1:'Bot',
    2:'DDoS',
    3:'DoS GoldenEye',
    4:'DoS Hulk',
    5:'DoS Slowhttptest',
    6:'DoS slowloris',
    7:'FTP-Patator',
    8:'Heartbleed',
    9:'Infiltration',
    10:'PortScan',
    11:'SSH-Patator',
    12:'Web Attack � Brute Force',
    13:'Web Attack � Sql Injection',
    14:'Web Attack � XSS'    
}


# List of features in the exact order
feature_order=[
   'Fwd Packet Length Max',
 'Fwd Packet Length Mean',
 'Bwd Packets/s',
 'Total Length of Fwd Packets',
 'Subflow Fwd Bytes',
 'Flow Packets/s',
 'Packet Length Std',
 'Flow IAT Mean',
 'Avg Fwd Segment Size',
 'Flow IAT Max',
 'Init_Win_bytes_backward',
 'Avg Bwd Segment Size',
 'Bwd Packet Length Mean',
 'Flow Duration',
 'Bwd Packet Length Std',
 'Bwd Packet Length Max',
 'Subflow Bwd Bytes',
 'Total Length of Bwd Packets',
 'Destination Port',
 'Packet Length Variance'
]
# def preprocess_input(user_input):
#     #convert input to the appropriate data types
#     for column in feature_order:
#         user_input[column] = float(user_input[column])
#     return pd.DataFrame([user_input])
def preprocess_input(user_input):
    """
    Converts user input values to float and returns a DataFrame
    user_input: dict of form inputs
    """
    processed_input = {}
    for column in feature_order:
        value = user_input.get(column)
        if value is None or value == '':
            raise ValueError(f"Missing value for {column}")
        try:
            processed_input[column] = float(value)
        except ValueError:
            raise ValueError(f"Invalid numeric value for {column}: {value}")
    return pd.DataFrame([processed_input])


from flask import Flask,jsonify
@app.route('/predict', methods=['GET', 'POST'])
def predict():
    result = None
    if request.method == 'POST':
        try:
            # Collect user input
            user_input = {}
            for column in feature_order:  # now column is a string
                value = request.form.get(column)
                if value is None or value.strip() == "":
                    value = 0
                user_input[column] = float(value)

            # Convert to DataFrame for model
            input_df = pd.DataFrame([user_input])

            # Make prediction
            prediction = loaded_model.predict(input_df)
            decoded_class = class_mapping_reverse.get(prediction[0], 'Unknown')

            # Set result to show on the same page
            result = f"Predicted Class: {decoded_class}"

        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('predict.html', feature_order=feature_order, result=result)

# #store the prediction temporarily
# last_prediction = []
# @app.route('/upload', methods=['GET', 'POST'])
# def upload_file():
#     global last_prediction
#     #check if the post request has the file part
#     if 'file' not in request.files:
#         return render_template('upload.html',error='No file part')
#     file = request.files['file']
#     #if the user does not select a file, the browser also
#     #submits an empty part without filename
#     if file.filename == '':
#         return render_template('upload.html',error='No selected file')
#     try:
#         #Read the csv file
#         df=pd.read_csv(file)
       
#         #Make predictions using the loaded model
#         predictions = loaded_model.predict(df)
#         #   Get the class names for prediction
#         class_names=[class_mapping_reverse.get(prediction,'Unknown') for prediction in predictions]

#         #convert the int64 types to native python integers
#         predictions=predictions.astype(np.int64).tolist() 

#         #prepare the response with both class index and class name
#         response=[{'sr_no': i+1,'class_index':prediction,'class_name':class_name} 
#                   for i, (prediction,class_name) in enumerate(zip(predictions,class_names))]

#         #Store the last prediction
#         last_prediction = response
        
#             # ============================================
#             # Visualization: Plot class distribution
#             # ============================================
#         plt.figure(figsize=(6, 4))
#         plt.title("Prediction Distribution")
#         plt.xlabel("Class")
#         plt.ylabel("Count")

#             # Count occurrences
#         class_counts = pd.Series(class_names).value_counts()
#         class_counts.plot(kind='bar', color=['skyblue', 'salmon', 'lightgreen'])
#         plt.xticks(rotation=45)
#         plt.tight_layout()

#             # Convert plot to base64 image
#         img = io.BytesIO()
#         plt.savefig(img, format='png')
#         img.seek(0)
#         plot_url = base64.b64encode(img.getvalue()).decode()
#         plt.close()

#         #Return the HTML page with predictions
#         return render_template('upload.html',predictions=response,plot_url=plot_url)
    

#     except Exception as e:
#         return render_template('upload.html',error=f"Error processing file: {str(e)}")
last_prediction = []           # Current upload predictions
cumulative_predictions = []    # All predictions cumulatively for dashboard

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    global last_prediction, cumulative_predictions

    if request.method == 'GET':
        return render_template('upload.html')

    # --- File Validation ---
    if 'file' not in request.files:
        return render_template('upload.html', error='No file part')
    
    file = request.files['file']
    if file.filename == '':
        return render_template('upload.html', error='No selected file')

    try:
        # --- Read CSV ---
        df = pd.read_csv(file)

        # --- Make Predictions ---
        predictions = loaded_model.predict(df)

        # --- Map prediction indices to class names ---
        class_names = [class_mapping_reverse.get(pred, 'Unknown') for pred in predictions]
        predictions = predictions.astype(np.int64).tolist()

        # --- Prepare response for table ---
        response = [
            {'sr_no': i + 1, 'class_index': pred, 'class_name': cname}
            for i, (pred, cname) in enumerate(zip(predictions, class_names))
        ]

        # --- Update last and cumulative predictions ---
        last_prediction.clear()
        last_prediction.extend(response)             # Current file
        cumulative_predictions.extend(response)      # Add to dashboard cumulative data

        # ============================================
        # Visualization 1: Matplotlib Bar Chart (Current File)
        # ============================================
    

        plt.figure(figsize=(6, 4))
        plt.title("Prediction Distribution")
        plt.xlabel("Class Name")
        plt.ylabel("Count")

        class_counts = pd.Series(class_names).value_counts()
        class_counts.plot(kind='bar', color=['#60a5fa', '#f87171', '#34d399', '#fbbf24', '#a78bfa'])
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Convert to base64
        img = io.BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plot_url = base64.b64encode(img.getvalue()).decode()
        plt.close()

        # ============================================
        # Visualization 2: Chart.js Doughnut Data (Current File)
        # ============================================
        attack_counts = class_counts.to_dict()

        # --- Render Template for upload page ---
        return render_template(
            'upload.html',
            predictions=response,
            plot_url=plot_url,
            attack_counts=attack_counts
        )

    except Exception as e:
        return render_template('upload.html', error=f"Error processing file: {str(e)}")

@app.route('/download_report')
def download_report():
    global last_prediction
    if not last_prediction:
        return Response("No predictions available to download.", mimetype='text/plain')
    #Create CSV content
    report_lines=["Intrusion Detection Report\n"]
    report_lines = ["Sr No,Class Index,Class Name\n"]
    for item in last_prediction:
        line = f"{item['sr_no']},{item['class_index']},{item['class_name']}\n"
        report_lines.append(line)   
    report_content = ''.join(report_lines)
    return Response(
        report_content,
        mimetype='text/csv',
        headers={'Content-Disposition':'attachment;filename=network_intrusion_report.csv'}
    )

@app.route('/about')
def about():
    return render_template('aboutus.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    global cumulative_predictions
    if 'email' not in session:
        flash("Please login to view profile", "error")
        return redirect('/login')

    # Get current user
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash("User not found", "error")
        return redirect('/login')

    # Handle password update
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        if not old_password or not new_password:
            flash("Please fill all password fields", "error")
            return redirect('/profile')

        if not user.check_password(old_password):
            flash("Old password is incorrect", "error")
            return redirect('/profile')

        # Update password
        user.set_password(new_password)

        db.session.commit()
        flash("Password updated successfully", "success")
        return redirect('/profile')

    # --- Dashboard Stats for profile page ---
    total_uploads = len(cumulative_predictions)       # Total files/predictions uploaded
    total_predictions = len(cumulative_predictions)  # Total predictions
    normal_count = sum(1 for p in cumulative_predictions if p['class_name'] == 'BENIGN')
    total_attacks = total_predictions - normal_count

    return render_template(
        'profile.html',
        user=user,
        total_uploads=total_uploads,
        total_predictions=total_predictions,
        total_attacks=total_attacks
    )

# #start packet capturing
# realtime_detector.start_capture_thread()


# @app.route('/realtime_dashboard')
# def realtime_dashboard():
#     # Provide summary stats to template (initial render)
#     if os.path.exists(LOG_FILE):
#         try:
#             df = pd.read_csv(LOG_FILE)
#         except Exception as e:
#             print("Error reading log:", e)
#             df = pd.DataFrame()

#         total = len(df)
#         if LABEL_COL in df.columns:
#             normal = int((df[LABEL_COL] == 'BENIGN').sum())
#             attack = total - normal
#             attack_counts = df[LABEL_COL].value_counts().to_dict()
#         else:
#             normal = 0
#             attack = 0
#             attack_counts = {}
#         accuracy = round((normal / total) * 100, 2) if total > 0 else 0
#     else:
#         total = normal = attack = accuracy = 0
#         attack_counts = {}

#     return render_template("realtime_dashboard.html",
#                            total_predictions=total,
#                            normal_count=normal,
#                            attack_count=attack,
#                            accuracy=accuracy,
#                            attack_counts=attack_counts)

# @app.route('/realtime_data')
# def realtime_data():
#     """
#     Returns an HTML fragment (table) showing the most recent detection rows.
#     HTMX will load this into the dashboard.
#     """
#     rows_html = []
#     if os.path.exists(LOG_FILE):
#         try:
#             df = pd.read_csv(LOG_FILE)
#         except Exception as e:
#             print("Failed to read log:", e)
#             df = pd.DataFrame()

#         # Use last 50 rows for live feed
#         tail = df.tail(50).copy()
#         # Normalize column names to expected keys
#         cols = [c.lower().strip() for c in tail.columns.tolist()]
#         tail.columns = cols

#         # build rows
#         for _, row in tail[::-1].iterrows():  # reversed: newest first
#             ts = row.get("timestamp", "")
#             label = row.get("label", "Unknown")
#             port = row.get("destination_port", "") or row.get("port", "")
#             avglen = row.get("avg_fwd_packet_len", "") or row.get("avglen", "")
#             dur = row.get("flow_duration", "")

#             color = "text-success" if str(label).upper() == "BENIGN" else "text-danger"
#             row_html = f"""
#             <tr>
#                 <td>{ts}</td>
#                 <td class="{color}">{label}</td>
#                 <td>{port}</td>
#                 <td>{avglen}</td>
#                 <td>{dur}</td>
#             </tr>
#             """
#             rows_html.append(row_html)
#     else:
#         rows_html.append("<tr><td colspan='5' class='text-center'>No data yet</td></tr>")

#     table_html = f"""
#     <table class="table table-striped">
#         <thead>
#             <tr>
#                 <th>Timestamp</th>
#                 <th>Label</th>
#                 <th>Destination Port</th>
#                 <th>Avg Fwd Len</th>
#                 <th>Flow Duration</th>
#             </tr>
#         </thead>
#         <tbody>
#             {''.join(rows_html)}
#         </tbody>
#     </table>
#     """
#     return table_html

# @app.route('/start_detection', methods=['POST'])
# def start_detection():
#     started = realtime_detector.start_capture_thread()
#     if started:
#         return ("", 204)
#     else:
#         return ("Already running", 200)
     
if __name__=='__main__':
    app.run(debug=True)