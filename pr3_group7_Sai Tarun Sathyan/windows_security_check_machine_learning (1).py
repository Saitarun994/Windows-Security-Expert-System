# -*- coding: utf-8 -*-
"""WINDOWS SECURITY CHECK - MACHINE LEARNING.ipynb

Automatically generated by Colaboratory.

Original file is located at
    https://colab.research.google.com/drive/1aq6HslINgrNgBZlqUblMIn6r5PgnewUO

"
             -------------------------------------------
            | WINDOWS SECURITY CHECK - MACHINE LEARNING |
             -------------------------------------------
Author: Sai Tarun Sathyan (SS4005)

""
"""

import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import LabelEncoder 
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

df = pd.read_excel("input_dataset.xlsx")
#df.head(10)
#df.info()
df.astype(float)
#df.describe()
#df.columns

plt.figure(figsize=(14, 12))
sns.heatmap(df.corr(), annot=True)
plt.show()

metric = df
scaler = StandardScaler()
metric = pd.DataFrame(scaler.fit_transform(metric), columns=metric.columns)
score = df["FINAL SCORE (10)"]

x_train = metric.iloc[:, :-1].values
y_train = metric.iloc[:, :-1].values
x_train, x_test, y_train, y_test = train_test_split(metric, score, train_size = 0.8)

model = LinearRegression()
model.fit(x_train, y_train)

print(f"Model R-Squared Value % {model.score(x_test, y_test)}") # testing accuracy

# Creating a pairplot
sns.pairplot(metric, x_vars = ['Password Check(2)', 'Pwd Strength (0->1)', 'Anti-Virus Check(2)',
       'Updates Check(1)', 'Firewall Status(2)', 'Bitlocker Status(2)'], y_vars = ["FINAL SCORE (10)"],
        size = 6, aspect = 0.6, kind = 'reg')

#creating logistic plot
ax = sns.regplot(x="FINAL SCORE (10)", y = 'Password Check(2)', data = metric,
       logistic = True, n_boot = 500, y_jitter = 0.3)

#creating logistic plot
ax = sns.regplot(x="FINAL SCORE (10)", y = "Pwd Strength (0->1)", data = metric,
       logistic = True, n_boot = 500, y_jitter = 0.3)