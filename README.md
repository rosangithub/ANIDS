# ANIDS
Anomaly Based Network Intrusion Detection System Using Ensemble Machine Learning
 Overview

This project aims to build a Network Intrusion Detection System (NIDS) that detects abnormal or malicious network traffic using Machine Learning algorithms.
The system analyzes network flow features to distinguish between normal and attack traffic efficiently.

It uses multiple classification algorithms and a Stacking Ensemble Model to improve detection accuracy and reduce false positives.
Technologies Used

Python

scikit-learn

pandas, numpy, matplotlib

CatBoost

joblib

Google Colab / Jupyter Notebook

GitHub / Git

Machine Learning Models Implemented

Logistic Regression

Decision Tree Classifier

K-Nearest Neighbors (KNN)

CatBoost Classifier

Random Forest Classifier (used as meta-model in stacking)

Stacking Ensemble Model (Hybrid Model)

The ensemble combines predictions from base learners to improve accuracy and generalization.

 Dataset

The dataset consists of multiple network traffic features such as:

Flow Duration

Total Length of Fwd Packets

Bwd Packets/s

Packet Length Std

Fwd Packet Length Mean

Destination Port

and others...

Data preprocessing included:

Handling missing values

Feature selection

Normalization

Train-test splitting

Model Evaluation Metrics

The system evaluates model performance using:

Accuracy

Precision

Recall

F1-score

Confusion Matrix (per class)
