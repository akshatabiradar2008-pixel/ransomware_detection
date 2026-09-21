from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import joblib
import pandas as pd
from collections import Counter

from utils.feature_extraction import analyze_file


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size = 100 MB
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


# =========================================================
# LOAD MACHINE LEARNING MODEL
# =========================================================

model = joblib.load(
    "model/ransomware_model.pkl"
)


# =========================================================
# STATISTICS
# =========================================================

statistics = {

    "total_files": 0,

    "high_risk": 0,

    "medium_risk": 0,

    "low_risk": 0,

    "total_suspicious_strings": 0,

    "total_entropy": 0.0,

    "file_types": Counter(),

    "recent_results": []

}


# =========================================================
# RANSOMWARE RISK ANALYSIS
# =========================================================

def generic_ransomware_check(stats):

    score = 0

    reasons = []


    # -----------------------------------------------------
    # ENTROPY
    # -----------------------------------------------------

    if stats["entropy"] >= 7.5:

        score += 2

        reasons.append(
            "Very high file entropy"
        )


    # -----------------------------------------------------
    # SUSPICIOUS STRINGS
    # -----------------------------------------------------

    if stats["suspicious_strings"] > 0:

        score += min(
            stats["suspicious_strings"] * 2,
            6
        )

        reasons.append(
            f"Found "
            f"{stats['suspicious_strings']} "
            f"suspicious string indicator(s)"
        )


    # -----------------------------------------------------
    # WINDOWS EXECUTABLE
    # -----------------------------------------------------

    if stats["is_pe"] == 1:

        score += 1

        reasons.append(
            "Windows executable detected"
        )


    # -----------------------------------------------------
    # LINUX EXECUTABLE
    # -----------------------------------------------------

    if stats["is_elf"] == 1:

        score += 1

        reasons.append(
            "Linux executable detected"
        )


    # -----------------------------------------------------
    # RISK LEVEL
    # -----------------------------------------------------

    if score >= 5:

        risk = "HIGH"

        alert = (
            "⚠️ SUSPICIOUS FILE - "
            "POSSIBLE RANSOMWARE"
        )


    elif score >= 3:

        risk = "MEDIUM"

        alert = (
            "⚠️ FILE REQUIRES "
            "FURTHER ANALYSIS"
        )


    else:

        risk = "LOW"

        alert = (
            "✅ NO STRONG RANSOMWARE "
            "INDICATORS FOUND"
        )


    return {

        "score": score,

        "risk": risk,

        "alert": alert,

        "reasons": reasons

    }


# =========================================================
# UPDATE STATISTICS
# =========================================================

def update_statistics(stats, risk):

    # Total files
    statistics["total_files"] += 1


    # Suspicious strings
    statistics["total_suspicious_strings"] += (
        stats["suspicious_strings"]
    )


    # Entropy
    statistics["total_entropy"] += (
        stats["entropy"]
    )


    # File extension
    extension = stats["extension"]

    if not extension:

        extension = "No extension"

    statistics["file_types"][extension] += 1


    # Risk level
    if risk["risk"] == "HIGH":

        statistics["high_risk"] += 1


    elif risk["risk"] == "MEDIUM":

        statistics["medium_risk"] += 1


    else:

        statistics["low_risk"] += 1


    # Recent analysis
    statistics["recent_results"].insert(

        0,

        {

            "filename":
                stats["filename"],

            "risk":
                risk["risk"],

            "score":
                risk["score"],

            "entropy":
                stats["entropy"]

        }

    )


    # Keep latest 10 files
    statistics["recent_results"] = (
        statistics["recent_results"][:10]
    )


# =========================================================
# CREATE DASHBOARD STATISTICS
# =========================================================

def get_dashboard_statistics():

    total = statistics["total_files"]


    # -----------------------------------------------------
    # DETECTION RATE
    # -----------------------------------------------------

    if total > 0:

        detection_rate = (

            (

                statistics["high_risk"]

                +

                statistics["medium_risk"]

            )

            / total

        ) * 100


        average_entropy = (

            statistics["total_entropy"]

            / total

        )


    else:

        detection_rate = 0

        average_entropy = 0


    return {

        "total_files":
            total,

        "high_risk":
            statistics["high_risk"],

        "medium_risk":
            statistics["medium_risk"],

        "low_risk":
            statistics["low_risk"],

        "detection_rate":
            round(
                detection_rate,
                2
            ),

        "average_entropy":
            round(
                average_entropy,
                4
            ),

        "total_suspicious_strings":
            statistics[
                "total_suspicious_strings"
            ],

        "file_types":
            dict(
                statistics["file_types"]
            ),

        "recent_results":
            statistics[
                "recent_results"
            ]

    }


# =========================================================
# MAIN PAGE
# =========================================================

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    filename = None

    stats = None

    risk = None

    ml_result = None


    # =====================================================
    # FILE UPLOAD
    # =====================================================

    if request.method == "POST":


        # -------------------------------------------------
        # CHECK FILE
        # -------------------------------------------------

        if "file" not in request.files:

            result = "No file selected"

            return render_template(

                "index.html",

                result=result,

                statistics=get_dashboard_statistics()

            )


        file = request.files["file"]


        # -------------------------------------------------
        # CHECK FILE NAME
        # -------------------------------------------------

        if file.filename == "":

            result = "No file selected"

            return render_template(

                "index.html",

                result=result,

                statistics=get_dashboard_statistics()

            )


        # -------------------------------------------------
        # SECURE FILE NAME
        # -------------------------------------------------

        filename = secure_filename(
            file.filename
        )


        if not filename:

            result = "Invalid filename"

            return render_template(

                "index.html",

                result=result,

                statistics=get_dashboard_statistics()

            )


        # -------------------------------------------------
        # FILE PATH
        # -------------------------------------------------

        filepath = os.path.join(

            app.config["UPLOAD_FOLDER"],

            filename

        )


        try:

            # -------------------------------------------------
            # SAVE FILE
            # -------------------------------------------------

            file.save(filepath)


            # -------------------------------------------------
            # ANALYZE FILE
            # -------------------------------------------------

            stats = analyze_file(
                filepath
            )


            # -------------------------------------------------
            # RANSOMWARE RISK
            # -------------------------------------------------

            risk = generic_ransomware_check(
                stats
            )


            result = risk["alert"]


            # -------------------------------------------------
            # UPDATE STATISTICS
            # -------------------------------------------------

            update_statistics(

                stats,

                risk

            )


            # =================================================
            # MACHINE LEARNING CSV ANALYSIS
            # =================================================

            if filename.lower().endswith(".csv"):

                try:

                    data = pd.read_csv(
                        filepath
                    )


                    # Select numeric features
                    numeric_data = (
                        data.select_dtypes(
                            include=["number"]
                        )
                    )


                    # Expected feature count
                    expected_features = (
                        model.n_features_in_
                    )


                    # -------------------------------------------------
                    # CHECK MODEL FEATURES
                    # -------------------------------------------------

                    if (
                        numeric_data.shape[1]
                        == expected_features
                    ):


                        # -------------------------------------------------
                        # PREDICTION
                        # -------------------------------------------------

                        prediction = model.predict(
                            numeric_data
                        )


                        confidence = None


                        # -------------------------------------------------
                        # CONFIDENCE
                        # -------------------------------------------------

                        if hasattr(
                            model,
                            "predict_proba"
                        ):

                            probabilities = (
                                model.predict_proba(
                                    numeric_data
                                )
                            )


                            confidence = (

                                probabilities
                                .max(axis=1)
                                .mean()
                                * 100

                            )


                        ml_result = {

                            "prediction":
                                prediction.tolist(),

                            "confidence":
                                (
                                    round(
                                        confidence,
                                        2
                                    )
                                    if confidence
                                    is not None
                                    else None
                                ),

                            "features":
                                expected_features

                        }


                    else:

                        ml_result = {

                            "error":

                                f"CSV contains "
                                f"{numeric_data.shape[1]} "
                                f"numeric features, "
                                f"but the trained model "
                                f"requires "
                                f"{expected_features}."

                        }


                except Exception as e:

                    print(
                        "ML ERROR:",
                        e
                    )

                    ml_result = {

                        "error":
                            "Unable to run the "
                            "ML model on this CSV."

                    }


        except Exception as e:

            print(
                "FILE ANALYSIS ERROR:",
                e
            )

            result = (
                "Unable to analyze this file."
            )


    # =====================================================
    # SEND EVERYTHING TO index.html
    # =====================================================

    return render_template(

        "index.html",

        result=result,

        filename=filename,

        stats=stats,

        risk=risk,

        ml_result=ml_result,

        statistics=get_dashboard_statistics()

    )


# =========================================================
# START FLASK
# =========================================================

if __name__ == "__main__":

    app.run(

        debug=True,

        host="127.0.0.1",

        port=5000

    )