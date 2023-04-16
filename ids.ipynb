#import
import tensorflow as tf
import numpy as np
import pandas as pd
from keras.layers import Input, LSTM, RepeatVector,TimeDistributed
from keras.models import Model
from keras.preprocessing import sequence
from tensorflow import keras
import socket
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import matplotlib.pyplot as plt
from keras.layers import Input, Dense, LSTM, Flatten, Reshape
from keras.models import Model
from sklearn.metrics import f1_score

#load dataset
df=pd.read_csv('C:\\Users\\91900\\Desktop\\project_code\\CICIDS2019\\DrDoS_NTP_data_data_5_per.csv')

# Remove missing and duplicate data
df = df.dropna()
df = df.drop_duplicates()
print(df.shape)

#view all columns
print(df.columns)

#find all fields with object datatype
obj_cols = df.select_dtypes(include=['object']).columns
print('df : ',obj_cols)

#rename column
df = df.rename(columns={' Label': 'Label'})
df = df.rename(columns={' Source IP': 'SourceIP'})
df = df.rename(columns={' Destination IP': 'DestinationIP'})
df = df.rename(columns={' Timestamp': 'Timestamp'})
df = df.rename(columns={' Fwd Header Length': 'Fwd Header Length'})

#drop 'Flow Id' and 'SimillarHttp'
df.drop(columns=['Flow ID'], inplace=True)
df.drop(columns=['SimillarHTTP'], inplace=True)
df.drop(columns=['DestinationIP'], inplace=True)
df.drop(columns=['SourceIP'], inplace=True)

# get the unique values from the 'label' column
print('df: ',df['Label'].unique())
df['Label'] = df['Label'].replace(to_replace='DrDoS_NTP', value=0)
df['Label'] = df['Label'].replace(to_replace='BENIGN', value=1)
print(df.Label.unique())

from sklearn.preprocessing import MinMaxScaler
#processing timestamp,(value was v large)
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['Timestamp'] = df['Timestamp'].astype('int64')
scaler = MinMaxScaler()
df['Timestamp'] = scaler.fit_transform(df['Timestamp'].values.reshape(-1, 1))


#find all fields with object datatype
obj_cols = df.select_dtypes(include=['object']).columns
print('df : ',obj_cols)

# Find the minimum and maximum values in the DataFrame
df_min = df.min().min()
df_max = df.max().max()
print("Minimum value in the DataFrame:", df_min)
print("Maximum value in the DataFrame:", df_max)

# Check for infinite values in each column
for col in df.columns:
    if np.isinf(df[col]).any():
        print(f"Column {col} has infinite values.")
        
print(df[' Flow Packets/s'].nunique())
print(df[' Flow Packets/s'].max())
print(df[' Flow Packets/s'].min())

# Replace inf with the maximum non-inf value
max_val = np.max(df[df[' Flow Packets/s'] != np.inf][' Flow Packets/s'])
df[' Flow Packets/s'].replace(np.inf, max_val, inplace=True)

# Apply Min-Max scaling to the Flow Packets/s column
scaler = MinMaxScaler()
df[' Flow Packets/s'] = scaler.fit_transform(df[[' Flow Packets/s']])


# Replace inf with the maximum non-inf value
max_val = np.max(df[df['Flow Bytes/s'] != np.inf]['Flow Bytes/s'])
df['Flow Bytes/s'].replace(np.inf, max_val, inplace=True)

# Apply Min-Max scaling to the Flow Packets/s column
scaler = MinMaxScaler()
df['Flow Bytes/s'] = scaler.fit_transform(df[['Flow Bytes/s']])

# find the column with the minimum value
min_col = df.idxmin(axis=1)
#max_col = df.idxmax(axis=1)
print(min_col)
#print('____________________________________________')
#print(max_col)

print('df : ',df.shape)

inputs = Input(shape=(1, 84))
x = LSTM(64, activation='relu', return_sequences=True)(inputs)
x = LSTM(32, activation='relu', return_sequences=True)(x)
encoded = LSTM(16, activation='relu', return_sequences=False)(x)

x = RepeatVector(1)(encoded)
x = LSTM(32, activation='relu', return_sequences=True)(x)
x = LSTM(64, activation='relu', return_sequences=True)(x)
decoded = TimeDistributed(Dense(84, activation='linear'))(x)

autoencoder = Model(inputs, decoded)

autoencoder.compile(optimizer='adam', loss='mean_squared_error')
autoencoder.summary()

# Perform feature extraction
X = df.values
X_norm = (X - np.min(X)) / (np.max(X) - np.min(X))
X_norm_reshaped = X_norm.reshape((X_norm.shape[0], 1, X_norm.shape[1]))

# Train the autoencoder model
history = autoencoder.fit(X_norm_reshaped, X_norm_reshaped, epochs=10, batch_size=64, validation_split=0.2)

encoder = Model(inputs=autoencoder.input, outputs=autoencoder.layers[2].output)

encoded_data = encoder.predict(X_norm_reshaped)

from sklearn.model_selection import train_test_split
# Get the encoded representation of the data
encoded_data = encoder.predict(X_norm_reshaped)

# Define X and y for splitting the data
X = encoded_data
y = df['Label']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Define the adversarial model
input_layer = Input(shape=(1, 32))
dense_layer = Dense(32, activation='relu')(input_layer)
reshaped_layer1 = Reshape((32,))(dense_layer)
reshaped_layer2 = Reshape((1, 32))(reshaped_layer1)
decoded_layer = autoencoder.layers[-2](reshaped_layer2)
decoded_layer = autoencoder.layers[-1](decoded_layer)
output_layer = Reshape((1, X_train.shape[2]))(decoded_layer)
adversarial = Model(input_layer, output_layer)
adversarial.compile(optimizer='adam', loss='mse')

print(adversarial.summary())


# Train the adversarial model
adversarial.fit(X_train, X_train, epochs=10, batch_size=32, validation_data=(X_test, X_test))

# Reshape the test data
X_test_reshaped = X_test.reshape(X_test.shape[0],1, X_test.shape[2])

# Encode the test data using the encoder model
encoded_test_data1 = autoencoder.predict(X_test_reshaped)

# Evaluate the model's performance for different threshold values
threshold_values = np.linspace(0, 1, 100)
f1_scores = []
for threshold in threshold_values:
    # Apply the threshold to the predictions to determine which feature vectors are anomalous
    binary_predictions = np.where(encoded_test_data1> threshold, 1, 0)
    
# Calculate the reconstruction error
reconstruction_error = np.mean(np.abs( encoded_test_data1 - X_test_reshaped), axis=2)

reconstruction_error

from sklearn.metrics import precision_score

# Reshape binary_predictions to remove the extra dimensions
binary_predictions = binary_predictions.reshape((binary_predictions.shape[0], binary_predictions.shape[2]))

# Convert binary_predictions to integer labels
y_pred = np.argmax(binary_predictions, axis=1)

# Calculate precision
precision = precision_score(y_test, y_pred, average='micro')
print(precision)

from sklearn.metrics import recall_score

# Calculate recall
recall = recall_score(y_test, y_pred, average='micro')

print(recall)

from sklearn.metrics import f1_score

# Calculate F1-Score
f1_score = f1_score(y_test, y_pred, average='micro')

print(f1_score)

from sklearn.metrics import confusion_matrix


# Calculate confusion matrix
confusion_matrix = confusion_matrix(y_test, y_pred)
print(confusion_matrix)

# Define the positive class label
pos_label = 1


# Extract true positives, false positives, true negatives, and false negatives
tp = confusion_matrix[pos_label, pos_label]
fp = confusion_matrix[:, pos_label].sum() - tp
tn = confusion_matrix[0, 0] + confusion_matrix[1, 1]  # Assumes 2 unique labels
fn = confusion_matrix[pos_label, :].sum() - tp

# Calculate TPR and FPR
tpr = tp / (tp + fn)
fpr = fp / (fp + tn)

print(tpr)#sensitivity
print(fpr)#fallout
