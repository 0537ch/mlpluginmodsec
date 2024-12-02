import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from nltk.corpus import stopwords
from sklearn.metrics import accuracy_score, f1_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
import tensorflow as tf
import numpy as np
from sklearn.metrics import confusion_matrix
from tensorflow.keras import models, layers
import warnings

warnings.filterwarnings('ignore')
#导入所需库
#df = pd.read_csv("../input/sql-injection-dataset/sqli.csv",encoding='utf-16')
#读取数据 指定文件编码方式
df = pd.read_csv("../input/d/sajid576/sql-injection-dataset/Modified_SQL_Dataset.csv")
#X = df['Sentence']
X = df['Query']
y = df['Label']
#提取了'Sentence'和'Label'列，分别作为特征向量X和标签向量y
vectorizer = CountVectorizer(min_df = 2, max_df = 0.8, stop_words = stopwords.words('english'))
X = vectorizer.fit_transform(X.values.astype('U')).toarray()
#使用CountVectorizer()将文本转换为数值特征，并将结果存储在X中

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state=1)
#使用train_test_split()函数将数据划分为训练集和测试集
print(X_train.shape)
print(y_train.shape)
print(X_test.shape)
print(y_test.shape)
#输出训练集和测试集的大小
(24735, 6594)
(24735,)
(6184, 6594)
(6184,)
nb_clf = GaussianNB()
#创建一个GaussianNB类的实例对象
nb_clf.fit(X_train, y_train)
#使用fit方法训练朴素贝叶斯分类器
y_pred = nb_clf.predict(X_test)
#使用predict方法在测试集上进行预测
#将测试结果存储到y_pred中

print(f"Accuracy of Naive Bayes on test set : {accuracy_score(y_pred, y_test)}")
print(f"F1 Score of Naive Bayes on test set : {f1_score(y_pred, y_test)}")
#计算并输出预测结果的精度(准确性)和F1
#F1为评估分类器的性能参数，（0，1），越大越好

#使用sklearn.metrics模块中的confusion_matrix函数计算混淆矩阵
#根据混淆矩阵计算了敏感性、特异性和精度
confusion = confusion_matrix(y_test, y_pred)
#返回一个2×2的矩阵，其中第i行第j列表示真实标签为第i类，预测结果为第j类的样本数（标签！）

TP = confusion[1, 1]
TN = confusion[0, 0]
FP = confusion[0, 1]
FN = confusion[1, 0]
#提取混淆矩阵的参数

#根据参数计算敏感性、特异性和精度（精确率）
sensitivity = TP / float(FN + TP)
print("sensitivity=",sensitivity)

specificity = TN / (TN + FP)
print("specificity=",specificity)

Precision = TP / float(TP + FP)
#Recall = TP / float(TP + FN)
#F1 = 2*((Precision*Recall)/(Precision+Recall))
print ("Precision=",Precision)

#accuracy_score()计算分类器的准确性 Precision()计算分类器的精确率

