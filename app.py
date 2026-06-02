

# ---- Import Libraries ----
import os
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime
from flask import (
    Flask, render_template, request,
    redirect, url_for, jsonify, send_file, session
)
from fpdf import FPDF

# ---- Initialize Flask App ----
app = Flask(__name__)
app.secret_key = 'network-intrusion-detection-2024'  # Required for session

# ---- Global variable to store analysis results ----
# (In a real app, you'd use a database; for simplicity, we use a global dict)
analysis_results = {}




def load_model():
    """
    Load the trained Random Forest model and preprocessing objects
    from the pickle file created by train_model.py.

    Returns:
        model_package: Dict containing:
            - model:          Trained RandomForestClassifier
            - label_encoders: Dict of LabelEncoders for categorical features
            - target_encoder: LabelEncoder for target labels
            - scaler:         StandardScaler for feature normalization
            - feature_names:  List of expected feature column names
    """
    model_path = os.path.join('model', 'intrusion_model.pkl')

    # Check if model file exists
    if not os.path.exists(model_path):
        print("[ERROR] Model not found! Run 'python train_model.py' first.")
        return None

    # Load the model package from pickle
    with open(model_path, 'rb') as f:
        model_package = pickle.load(f)

    return model_package




def load_model_comparison():
    """
    Load the model comparison results (accuracy of all 3 models)
    from the JSON file created during training.
    """
    comparison_path = os.path.join('model', 'model_comparison.json')

    if not os.path.exists(comparison_path):
        # Return default values if file doesn't exist
        return {
            'Random Forest':      {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0},
            'Decision Tree':      {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0},
            'Logistic Regression': {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
        }

    with open(comparison_path, 'r') as f:
        return json.load(f)




def preprocess_upload(df, model_package):
    """
    Preprocess an uploaded CSV file to match the format
    expected by the trained model.

    Steps:
        1. Select only the features the model expects
        2. Encode categorical columns using saved encoders
        3. Scale numerical features using saved scaler

    Args:
        df: pandas DataFrame from uploaded CSV
        model_package: Dict with model and preprocessing objects

    Returns:
        X_processed: Preprocessed feature matrix ready for prediction
        success: Boolean indicating if preprocessing worked
        error_msg: Error message if preprocessing failed
    """
    label_encoders = model_package['label_encoders']
    scaler = model_package['scaler']
    feature_names = model_package['feature_names']

    # Expected feature columns (without 'label')
    expected_features = [f for f in feature_names]

    # Check if all required columns exist in the uploaded file
    missing_cols = [col for col in expected_features if col not in df.columns]
    if missing_cols:
        return None, False, f"Missing columns: {', '.join(missing_cols)}"

    # Select only the columns we need (in the correct order)
    X = df[expected_features].copy()

    # Encode categorical columns
    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in X.columns:
            le = label_encoders[col]
            # Handle unseen categories by mapping to the most common class
            known_classes = set(le.classes_)
            X[col] = X[col].apply(
                lambda val: val if val in known_classes else le.classes_[0]
            )
            X[col] = le.transform(X[col])

    # Scale features using the same scaler from training
    X_processed = pd.DataFrame(
        scaler.transform(X),
        columns=feature_names
    )

    return X_processed, True, ""




def get_risk_level(prediction):
    """
    Assign a risk level based on the attack type.

    Risk levels:
        Low    -> Normal traffic (safe)
        Medium -> Probe attacks (reconnaissance)
        High   -> DoS, R2L, or U2R attacks (dangerous)
    """
    if prediction == 'normal':
        return 'Low'
    elif prediction == 'probe':
        return 'Medium'
    else:
        return 'High'



def get_severity(attack_percentage):
    """
    Determine overall severity based on attack percentage.

    Returns:
        'safe'      -> Less than 20% attacks (green)
        'warning'   -> 20-50% attacks (yellow)
        'dangerous' -> More than 50% attacks (red)
    """
    if attack_percentage < 20:
        return 'safe'
    elif attack_percentage < 50:
        return 'warning'
    else:
        return 'dangerous'




@app.route('/')
def index():
    """
    Render the home page with the CSV upload form.
    """
    return render_template('index.html')




@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Process the uploaded CSV file:
    1. Read the CSV data
    2. Preprocess it for the model
    3. Make predictions using Random Forest
    4. Calculate statistics
    5. Store results and redirect to dashboard
    """
    global analysis_results

    # ---- Check if a file was uploaded ----
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        return redirect(url_for('index'))

    # ---- Read the CSV file ----
    try:
        df = pd.read_csv(file)
    except Exception as e:
        return render_template('index.html', error=f"Error reading CSV: {str(e)}")

    # ---- Load the trained model ----
    model_package = load_model()
    if model_package is None:
        return render_template('index.html',
                               error="Model not found! Please run 'python train_model.py' first.")

    # ---- Preprocess the data ----
    X_processed, success, error_msg = preprocess_upload(df, model_package)
    if not success:
        return render_template('index.html', error=error_msg)

    # ---- Make Predictions ----
    model = model_package['model']
    target_encoder = model_package['target_encoder']

    # Get predictions (numeric)
    predictions_numeric = model.predict(X_processed)

    # Get prediction probabilities for confidence scores
    prediction_probs = model.predict_proba(X_processed)

    # Convert numeric predictions back to labels
    predictions_labels = target_encoder.inverse_transform(predictions_numeric)

    # ---- Build Results ----
    total_records = len(df)
    normal_count = int(np.sum(predictions_labels == 'normal'))
    attack_count = total_records - normal_count

    # Calculate attack percentage
    attack_percentage = (attack_count / total_records * 100) if total_records > 0 else 0

    # Build per-record predictions list
    predictions_list = []
    for i in range(total_records):
        # Confidence = probability of the predicted class
        confidence = round(float(np.max(prediction_probs[i])) * 100, 1)
        predictions_list.append({
            'id':         i + 1,
            'prediction': predictions_labels[i].upper(),
            'confidence': confidence,
            'risk_level': get_risk_level(predictions_labels[i])
        })

    # Count each attack type
    attack_distribution = {}
    for label in ['dos', 'probe', 'r2l', 'u2r']:
        count = int(np.sum(predictions_labels == label))
        if count > 0:
            attack_distribution[label.upper()] = count

    # Load model comparison metrics
    model_comparison = load_model_comparison()

    # Get Random Forest metrics (our deployed model)
    rf_metrics = model_comparison.get('Random Forest', {})

    # Build model comparison list for charts
    comparison_list = []
    for model_name, metrics in model_comparison.items():
        comparison_list.append({
            'name':     model_name,
            'accuracy': metrics['accuracy']
        })

    # ---- Store all results ----
    analysis_results = {
        'timestamp':           datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_records':       total_records,
        'normal_count':        normal_count,
        'attack_count':        attack_count,
        'attack_percentage':   round(attack_percentage, 1),
        'predictions':         predictions_list,
        'attack_distribution': attack_distribution,
        'metrics': {
            'accuracy':  rf_metrics.get('accuracy', 0),
            'precision': rf_metrics.get('precision', 0),
            'recall':    rf_metrics.get('recall', 0),
            'f1':        rf_metrics.get('f1', 0)
        },
        'model_comparison':    comparison_list,
        'severity_level':      get_severity(attack_percentage)
    }

    # Redirect to dashboard to show results
    return redirect(url_for('dashboard'))




@app.route('/dashboard')
def dashboard():
    """
    Render the analysis dashboard with all results.
    If no analysis has been done yet, redirect to home.
    """
    global analysis_results

    # If no results yet, redirect to home page
    if not analysis_results:
        return redirect(url_for('index'))

    return render_template('dashboard.html', results=analysis_results)



@app.route('/api/results')
def api_results():
    """
    Return analysis results as JSON.
    Used by JavaScript to populate charts dynamically.
    """
    global analysis_results

    if not analysis_results:
        return jsonify({'error': 'No analysis results available'}), 404

    return jsonify(analysis_results)



@app.route('/download-report')
def download_report():
    """
    Generate and download a PDF report of the analysis results.
    Uses fpdf2 library for PDF generation.
    """
    global analysis_results

    if not analysis_results:
        return redirect(url_for('index'))

    # ---- Create PDF ----
    pdf = FPDF()
    pdf.add_page()

    # Title
    pdf.set_font('Helvetica', 'B', 20)
    pdf.cell(0, 15, 'Network Intrusion Detection Report', align='C', new_x='LMARGIN', new_y='NEXT')

    # Separator line
    pdf.set_draw_color(0, 200, 200)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(10)

    # Analysis Info
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, 'Analysis Summary', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 7, f"Date: {analysis_results['timestamp']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"Total Records Analyzed: {analysis_results['total_records']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"Normal Traffic: {analysis_results['normal_count']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"Attacks Detected: {analysis_results['attack_count']}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"Severity Level: {analysis_results['severity_level'].upper()}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    # Attack Distribution
    if analysis_results['attack_distribution']:
        pdf.set_font('Helvetica', 'B', 14)
        pdf.cell(0, 10, 'Attack Distribution', new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('Helvetica', '', 11)
        for attack_type, count in analysis_results['attack_distribution'].items():
            pdf.cell(0, 7, f"  {attack_type}: {count} records", new_x='LMARGIN', new_y='NEXT')
        pdf.ln(5)

    # Model Performance
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, 'Model Performance (Random Forest)', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 11)
    metrics = analysis_results['metrics']
    pdf.cell(0, 7, f"  Accuracy:  {metrics['accuracy']:.2%}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"  Precision: {metrics['precision']:.2%}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"  Recall:    {metrics['recall']:.2%}", new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 7, f"  F1 Score:  {metrics['f1']:.2%}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    # Model Comparison
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, 'Model Comparison', new_x='LMARGIN', new_y='NEXT')
    pdf.set_font('Helvetica', '', 11)
    for comp in analysis_results['model_comparison']:
        pdf.cell(0, 7, f"  {comp['name']}: {comp['accuracy']:.2%}", new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    # Predictions Table Header
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, 'Predictions Summary', new_x='LMARGIN', new_y='NEXT')

    # Table header
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_fill_color(0, 50, 80)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(25, 8, 'Record', border=1, fill=True, align='C')
    pdf.cell(50, 8, 'Prediction', border=1, fill=True, align='C')
    pdf.cell(35, 8, 'Confidence', border=1, fill=True, align='C')
    pdf.cell(35, 8, 'Risk Level', border=1, fill=True, align='C')
    pdf.ln()

    # Table rows (limit to first 50 for readability)
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(0, 0, 0)
    for pred in analysis_results['predictions'][:50]:
        pdf.cell(25, 7, str(pred['id']), border=1, align='C')
        pdf.cell(50, 7, pred['prediction'], border=1, align='C')
        pdf.cell(35, 7, f"{pred['confidence']}%", border=1, align='C')
        pdf.cell(35, 7, pred['risk_level'], border=1, align='C')
        pdf.ln()

    if len(analysis_results['predictions']) > 50:
        pdf.ln(3)
        pdf.set_font('Helvetica', 'I', 9)
        remaining = len(analysis_results['predictions']) - 50
        pdf.cell(0, 7, f"... and {remaining} more records (showing first 50)",
                 new_x='LMARGIN', new_y='NEXT')

    # Footer
    pdf.ln(10)
    pdf.set_font('Helvetica', 'I', 9)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 7, 'Generated by Network Intrusion Detection System', align='C',
             new_x='LMARGIN', new_y='NEXT')

    # ---- Save and Send PDF ----
    report_path = os.path.join('static', 'report.pdf')
    os.makedirs('static', exist_ok=True)
    pdf.output(report_path)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"intrusion_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )




@app.route('/report')
def report():
    """
    Render a printable HTML report page.
    """
    global analysis_results

    if not analysis_results:
        return redirect(url_for('index'))

    return render_template('report.html', results=analysis_results)




if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("  [NIDS] Network Intrusion Detection System")
    print("  [WEB]  Open: http://127.0.0.1:5000")
    print("=" * 50 + "\n")
    app.run(debug=True, port=5000)
