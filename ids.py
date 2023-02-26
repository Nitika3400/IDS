import tensorflow as tf
import numpy as np
import pandas as pd
from keras.layers import Input, LSTM, RepeatVector
from keras.models import Model
from keras.preprocessing import sequence
from sklearn.preprocessing import RobustScaler
import socket
from sklearn.model_selection import train_test_split

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

df = df.rename(columns={' Label': 'Label'})
df = df.rename(columns={' Source IP': 'SourceIP'})
df = df.rename(columns={' Destination IP': 'DestinationIP'})
df = df.rename(columns={' Timestamp': 'Timestamp'})
df = df.rename(columns={' Fwd Header Length': 'Fwd Header Length'})

#could'nt convert to a numeric datatype
#drop 'Flow Id' and 'SimillarHttp'
df.drop(columns=['Flow ID'], inplace=True)
df.drop(columns=['SimillarHTTP'], inplace=True)

# get the unique values from the 'label' column
print('df: ',df['Label'].unique())
df['Label'] = df['Label'].replace(to_replace='DrDoS_NTP', value=0)
df['Label'] = df['Label'].replace(to_replace='BENIGN', value=1)
print(df.Label.unique())

#processing timestamp,(value was v large)
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['Timestamp'] = df['Timestamp'].astype('int64')
mean_val = np.mean(df['Timestamp'])
std_val = np.std(df['Timestamp'])
df['Timestamp'] = (df['Timestamp'] - mean_val) / std_val
timestamp_tensor = tf.convert_to_tensor(df['Timestamp'].values)
print(df['Timestamp'].nunique())

#find all fields with object datatype
obj_cols = df.select_dtypes(include=['object']).columns
print('df : ',obj_cols)

'''
# Find the minimum and maximum values in the DataFrame
df_min = df.min().min()
df_max = df.max().max()

print("Minimum value in the DataFrame:", df_min)
print("Maximum value in the DataFrame:", df_max)

# find the column with the minimum value
min_col = df.idxmin(axis=1)
max_col = df.idxmax(axis=1)
print(min_col)
print('____________________________________________')
print(max_col)
'''
'''
# Check for infinite values in each column
for col in df.columns:
    if np.isinf(df[col]).any():
        print(f"Column {col} has infinite values.")
        
'''

#has inf values
mean_val = np.mean(df[' Flow Packets/s'])
std_val = np.std(df[' Flow Packets/s'])
df[' Flow Packets/s'] = (df[' Flow Packets/s'] - mean_val) / std_val
timestamp_tensor = tf.convert_to_tensor(df[' Flow Packets/s'].values)
print(df[' Flow Packets/s'].nunique())
print(df[' Flow Packets/s'].max())
print(df[' Flow Packets/s'].min())

#has inf values
mean_val = np.mean(df['Flow Bytes/s'])
std_val = np.std(df['Flow Bytes/s'])
df['Flow Bytes/s'] = (df['Flow Bytes/s'] - mean_val) / std_val
timestamp_tensor = tf.convert_to_tensor(df['Flow Bytes/s'].values)
print(df['Flow Bytes/s'].nunique())
print(df['Flow Bytes/s'].max())
print(df['Flow Bytes/s'].min())

#has v small values
mean_val = np.mean(df['Init_Win_bytes_forward'])
std_val = np.std(df['Init_Win_bytes_forward'])
df['Init_Win_bytes_forward'] = (df['Init_Win_bytes_forward'] - mean_val) / std_val
timestamp_tensor = tf.convert_to_tensor(df['Init_Win_bytes_forward'].values)
print(df['Init_Win_bytes_forward'].nunique())
print(df['Init_Win_bytes_forward'].max())
print(df['Init_Win_bytes_forward'].min())

#has v small values
mean_val = np.mean(df['Init_Win_bytes_backward'])
std_val = np.std(df['Init_Win_bytes_backward'])
df['Init_Win_bytes_backward'] = (df['Init_Win_bytes_backward'] - mean_val) / std_val
timestamp_tensor = tf.convert_to_tensor(df['Init_Win_bytes_backward'].values)
print(df['Init_Win_bytes_backward'].nunique())
print(df['Init_Win_bytes_backward'].max())
print(df['Init_Win_bytes_backward'].min())
'''
from sklearn.preprocessing import MinMaxScaler
scaler =MinMaxScaler().fit(x_train)
x_train = scaler.transform(x_train)
scaler =MinMaxScaler().fit(y_train)
y_train = scaler.transform(y_train)
'''
'''
# Split the data into features and labels
x = df.drop(columns=['Label'])
y = df['Label']
# Split the data into training and test sets
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

x_train = np.reshape(train_data, (train_data.shape[0], 10, 86))
y_test = np.reshape(test_data, (test_data.shape[0], 10, 86))


#OR

#taking small values
df=df.tail(5000)
df1=df.head(5000)

X = df.iloc[:,0:84]
Y = df.iloc[:,85].values.reshape(-1,1)
C = df1.iloc[:,0:84]
T = df1.iloc[:,85].values.reshape(-1,1)
'''

'''

# Set the parameters for the LSTM layers

dropout_rate = 0.01
decay_rate = 0.01
timesteps = 10
input_dim = 86
# Define the model
model = keras.Sequential()

# Add the first LSTM encoder layer
model.add(keras.layers.LSTM(128, dropout=dropout_rate, kernel_regularizer=keras.regularizers.l2(decay_rate), return_sequences=True, input_shape=(timesteps, input_dim)))

# Add the second LSTM encoder layer
model.add(keras.layers.LSTM(64, dropout=dropout_rate, kernel_regularizer=keras.regularizers.l2(decay_rate)))

# Add the reshape layer to prepare for the decoder
model.add(keras.layers.Reshape((1, 64)))

# Add the first LSTM decoder layer
model.add(keras.layers.LSTM(64, dropout=dropout_rate, kernel_regularizer=keras.regularizers.l2(decay_rate), return_sequences=True))

# Add the second LSTM decoder layer
model.add(keras.layers.LSTM(128, dropout=dropout_rate, kernel_regularizer=keras.regularizers.l2(decay_rate)))

# Add the output layer
model.add(keras.layers.Dense(input_dim))

print(model.summary())

# Compile the autoencoder
autoencoder.compile(loss='mean_squared_error', optimizer='adam')

# Train the autoencoder
autoencoder.fit(x_train, x_train, epochs=5, batch_size=64, validation_data=(x_test, x_test))


# Build the adversarial model
adversarial_input = keras.Input(shape=(timesteps, input_dim))
adversarial_output = autoencoder(adversarial_input)
adversarial_model = keras.Model(inputs=adversarial_input, outputs=adversarial_output)

# Compile the adversarial model
adversarial_model.compile(loss='mean_squared_error', optimizer='adam')
'''
'''
print('dataset: ',df.shape)
print('model: ',model.summary())
print('input shape: ',model.layers[0].input_shape)
'''
'''
# use the trained autoencoder to get the reconstruction errors
train_pred = autoencoder.predict(train_data)
train_error = np.mean(np.power(train_data - train_pred, 2), axis=1)
test_pred = autoencoder.predict(test_data)
test_error = np.mean(np.power(test_data - test_pred, 2), axis=1)

# calculate the threshold value based on the training reconstruction errors
threshold = np.mean(train_error) + 3*np.std(train_error)

# flag any data points with a reconstruction error above the threshold value
flagged_data = data[data.apply(lambda x: np.mean(np.power(x - autoencoder.predict(x.reshape(1,-1)), 2), axis=1)[0] > threshold)]

'''
'''
# Evaluate the model's performance for different threshold values
threshold_values = np.linspace(0, 1, 100)
f1_scores = []
for threshold in threshold_values:
  # Use the adversarial model to make predictions on the test set
  predictions = adversarial_model.predict(x_test)

  # Compute the number of true positives, true negatives, false positives, and false negatives
  tp = 0
  tn = 0
  fp = 0
  fn = 0
  for i in range(len(predictions)):
    if np.linalg.norm(predictions[i] - x_test[i]) > threshold:
        print("Potential intrusion detected at index:", i)
      if y_test[i] == 1:
        tp += 1
      else:
        fp += 1
    else:
      if y_test[i] == 1:
        fn += 1
      else:
        tn += 1
  
  # Use the adversarial model to flag any deviations from the normal behavior as potential intrusions
predictions = adversarial_model.predict(x_test)
for i in range(len(predictions)):
  if np.linalg.norm(predictions[i] - x_test[i]) > threshold:
    print("Potential intrusion detected at index:", i)
    
  # Compute the precision, recall, and F1 score
  precision = tp / (tp + fp)
  recall = tp / (tp + fn)
  f1 = 2 * (precision * recall) / (precision + recall)
  f1_scores.append(f1)
  '''
  
