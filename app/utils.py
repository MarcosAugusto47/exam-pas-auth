import pandas as pd
#from pandas.api.types import CategoricalDtype
import pickle
#import config

import sys
import smart_open
sys.path.append("pipelines/")
from models.config import FEATURES as MODEL_FEATURES
from features.build_features import add_stats_features, add_pseudo_argumento_final


with open('models/xgboost_categorical_not_calibrated.pickle', 'rb') as f:
    model = pickle.load(f)


with smart_open.open("app/encodings/encoding_category.pickle", "rb") as f:
    cat_type = pickle.load(f)


approved_stats = pd.read_parquet('data/interim/approved_stats_convocation_2019_2021.parquet')

def preprocess_input_features2(
        user_features: dict,
        model_features: list,
) -> pd.DataFrame:
    """ Preprocess a new single sample of data to be predicted.

    Receive a dictionary with the user_features, adds engineered features,
    categorizes the course information and convert to a pandas dataframe.

    Args:
        user_features: list of features that the user gives.
        model_features: complete list of features that the model uses.

    Returns:
        A pandas dataframe with single row.
    """
    new_sample = user_features
    new_sample = pd.DataFrame([new_sample])

    new_sample = add_pseudo_argumento_final(new_sample)
    new_sample = add_stats_features(new_sample, approved_stats)

    #cat_type = CategoricalDtype(categories=config.COURSE_NAMES)
    new_sample.course = new_sample.course.astype(cat_type)
    new_sample = new_sample.reindex(columns=model_features)

    return new_sample


# def preprocess_input_features(features: dict) -> pd.DataFrame:
#     new_sample = features
#     new_sample = pd.DataFrame([new_sample])
#     cat_type = CategoricalDtype(categories=config.COURSE_NAMES)
#     new_sample.course = new_sample.course.astype(cat_type)
#     return new_sample


def predict_approval(new_data: pd.DataFrame) -> float:
    """Predicts the probability of approval.
    
    Computes the probability of the student of approval according to
    input data.
    
    Args:
        new_data: pandas Dataframe as a single row that has the features values
            of the student.

    Returns:
        Prediction of approval as a float probability.
    """
    new_data = preprocess_input_features2(new_data, model_features=MODEL_FEATURES)
    predictions = model.predict_proba(new_data)
    approval_prob = predictions[0][1]

    return round(float(approval_prob)*100, ndigits=1)


if __name__=="__main__":

    sample_approved = {
                        "escore_bruto_p1_etapa1": 6.034,
                        "escore_bruto_p2_etapa1": 64.65,
                        #"nota_redacao_etapa1": 9.733,
                        "escore_bruto_p1_etapa2": 3.845,
                        "escore_bruto_p2_etapa2": 63.826,
                        #"nota_redacao_etapa2": 9.933,
                        "escore_bruto_p1_etapa3": 7.14,
                        "escore_bruto_p2_etapa3": 76.636,
                        #"nota_redacao_etapa3": 9.931,
                        #"pseudo_argumento_final": 70.36833333333334,
                        #"min_flag": True,
                        #"median_flag": True,
                        #"cotista": 0,
                        "cotas_negros_flag": 0,
                        #"publicas_flag": 0,
                        "publicas1_flag": 0,
                        "publicas2_flag": 0,
                        "publicas3_flag": 0,
                        "publicas4_flag": 0,
                        "publicas5_flag": 0,
                        "publicas6_flag": 0,
                        "publicas7_flag": 0,
                        "publicas8_flag": 0,
                        "course": "MEDICINA (BACHARELADO)"
                    }
                        
    predictions = predict_approval(sample_approved)
    print(predictions)
