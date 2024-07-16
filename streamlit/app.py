import streamlit as st
import pandas as pd
import pymongo
import plotly.express as px

# MongoDB connection
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["backend"]
collection = db["parking_slots"]

# Fetch data
data = collection.find()
df = pd.DataFrame(list(data))

# Data preprocessing
df['Waktu'] = pd.to_datetime(df['Waktu'], format='%Y-%m-%d %H:%M:%S')
df = df.sort_values(by='Waktu')

# Add a 'Time of Day' column
def time_of_day(hour):
    if 0 <= hour < 12:
        return 'Pagi'
    elif 12 <= hour < 15:
        return 'Siang'
    elif 15 <= hour < 18:
        return 'Sore'
    else:
        return 'Malam'

df['Time of Day'] = df['Waktu'].dt.hour.apply(time_of_day)

# Streamlit app
st.title("Parking Slots Data Visualization Dashboard")

# Sidebar for time of day selection
time_of_day_options = ['Pagi', 'Siang', 'Sore', 'Malam']
selected_time_of_day = st.sidebar.selectbox("Select a time of day", time_of_day_options)

# Filter data by selected time of day
df_filtered = df[df['Time of Day'] == selected_time_of_day]

# Group by 'Waktu' date and hour to get total 'Belum terisi' by hour
df_filtered['Hour'] = df_filtered['Waktu'].dt.hour
hourly_data = df_filtered.groupby([df_filtered['Waktu'].dt.date, 'Hour']).agg({'Belum terisi': 'sum'}).reset_index()
hourly_data.columns = ['Date', 'Hour', 'Total Belum terisi']

# Display filtered data
st.write(f"### Raw Data for {selected_time_of_day}")
st.dataframe(df_filtered)

# Visualization: Total 'Belum terisi' Over Time by Hour
st.write(f"### Total 'Belum terisi' Over Time by Hour ({selected_time_of_day})")
fig_hourly = px.line(hourly_data, x='Hour', y='Total Belum terisi', color='Date',
                     title=f"Total 'Belum terisi' Over Time by Hour ({selected_time_of_day})")
st.plotly_chart(fig_hourly)

# Group by 'Waktu' date to get total 'Belum terisi' by date
state_data = df_filtered.groupby(df_filtered['Waktu'].dt.date).agg({'Belum terisi': 'sum'}).reset_index()
state_data.columns = ['Date', 'Total Belum terisi']


