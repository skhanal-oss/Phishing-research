# Phishing Detection Integrating Lexical and SSL/TLS Features

This repository contains the empirical research framework, source code, and datasets to evaluate whether incorporating SSL/TLS certificate-based features into a lexical-only Machine Learning baseline reduces false positive rates in phishing website detection. 

As phishing campaigns have started adpoting HTTPS and valid SSL/TLS certificates, lexical-only models suffer from high false positive rates, misclassifying benign sites and eroding trust in users. This study investigates the power of hybrid models using historical Certificate Transparency (CT) logs to bypass the limitations of offline/short-lived phishing URLs.

Project Overview & Objectives

## 📍 Project Overview and Objectives

The core research question is:  *" To what extent does adding SSL/TLS-based features to a lexcial machine learning model reduce false positives compared to a lexical-only baseline in phishing website detection?"*

### 🎯 Key Objectives:

#### 1. Replicable Baseline: 
Develop a robust lexical-only ML model using token patterns, length, and Shannon entropy.
#### 2. Feature Importance: 
Quantify the exact impact and predictive power of indivisual SSL/TLS features.
#### 3. Comparative Benchmarking:
Evaluate models using Accuracy, F1-Score, Recall, Precision, and False Positive Rate (FPR) across XGBoost, Random Forest, and Logistic Regression.
#### 4. Statistical Validation: 
Use McNemar's Test to confirm whether performance variances are statistically significant. 
#### 5. Practical Guidelines:
Output actionable deployment recommendation trade-offs for security developers. 


## 📂 Folder Structure
The project is organized as follows:
- data: datasets
- notebooks: Jupyter notebooks
- scripts: Python scripts
- results: outputs and graphs
- literature: research papers
- report: final report

## 👨‍💻 How to Run
#### Prerequisites
Ensure you have Python 3.10+ installed.

### 1. Clone the Repository
````
git clone https://github.com/skhanal-oss/Phishing-research
cd phishing-research
````

### 2. Environment Setup
Create a virtual environment and install the required library configurations:
````
python -m venv venv
source venv/bin/activate #For Windows: venv\Scripts\activate
pip install -r requirements.txt

````
*(Note: Your ````requirements.txt```` should include packages like ````scikit-learn````, ````xgboost````, ````pandas````, ````numpy````, ````requests````, and ````statsmodels```` for McNemar's test).*

### 3. Running the Scirpts in order

## ⚙️ Tools Used/Tech Stack: 
- Core Language: Python 3.10 + 
- Data Processing: Pandas & NumPy
- Machine Learning: XGBoost, Scikit-Learn *(Implements Random Forest and Logistic Regression baseline)*
- 
- (will add other here later)

## 📊 Results and Evaluation Metrics
Models are benchmarked against:
- False Positive Rate (FPR) *(Primary Focus)*
- Precision, Recall, and F1-score
- Confusion Matrix Analysis *(Performed to find which genuine sites are vulnerable to misclassification)*
- McNemar's Test Matrix *(A non-parametric statistical test applied to check the paired classification error rates of the baseline vs. hybrid frameworks.)*

## 📃 References
[1] Thomas, K., Li, F., Zand, A., Barrett, J., Ranieri, J., Invernizzi, L., Markov, Y., Comanescu, O., Eranti, V., Moscicki, A., 
Margolis, D., Paxson, V., & Bursztein, E. (2017). Data breaches, phishing, or malware? Understanding the risks of 
stolen credentials. In Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security 
(pp. 1421–1434). ACM. https://doi.org/10.1145/3133956.3134067 
[2] Marchal, S., François, J., State, R., & Engel, T. (2014). PhishStorm: Detecting phishing with streaming analytics. IEEE 
Transactions on Network and Service Management, 11(4), 458–471. https://doi.org/10.1109/TNSM.2014.2377295 
[3] Verma, R., & Das, A. (2017). What’s in a URL: Fast feature extraction and malicious URL detection. In Proceedings of 
the 3rd ACM International Workshop on Security and Privacy Analytics (IWSPA ’17) (pp. 55–63). ACM. 
https://doi.org/10.1145/3041008.3041016 
[4] Sahingoz, O. K., Buber, E., Demir, O., & Diri, B. (2019). Machine learning based phishing detection from URLs. Expert 
Systems with Applications, 117, 345–357. https://doi.org/10.1016/j.eswa.2018.09.029 
[5] Rao, R. S., & Pais, A. R. (2019). Detection of phishing websites using an efficient feature-based machine learning 
framework. Neural Computing and Applications, 31(8), 3851–3873. https://doi.org/10.1007/s00521-017-3305-0 
[6] Bahnsen, A. C., Bohorquez, E. C., Villegas, S., Vargas, J., & González, F. A. (2017). Classifying phishing URLs using 
recurrent neural networks. In Proceedings of the 2017 APWG Symposium on Electronic Crime Research (eCrime) 
(pp. 1–8). IEEE. https://doi.org/10.1109/ECRIME.2017.7945048 
[7] Abdelhamid, N., Ayesh, A., & Thabtah, F. (2014). Phishing detection based associative classification data mining. Expert 
Systems with Applications, 41(13), 5948–5959. https://doi.org/10.1016/j.eswa.2014.03.019

  


