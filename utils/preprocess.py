import pandas as pd
import logging

def preprocess_data(data_df, scaler, features, drop_cols):
    try:
        for feature in features:
            if feature not in data_df.columns:
                data_df[feature] = 0
        data_df = data_df.drop(columns=[col for col in drop_cols if col in data_df.columns], errors='ignore')
        numerical_cols = data_df.select_dtypes(include=['int64', 'float64']).columns
        if numerical_cols.empty:
            raise ValueError("No numerical columns to scale.")
        logging.info(f"Columns before scaling: {data_df.columns.tolist()}")
        data_df[numerical_cols] = scaler.transform(data_df[numerical_cols])
        return data_df
    except Exception as e:
        logging.error(f"Error in preprocessing: {e}")
        raise