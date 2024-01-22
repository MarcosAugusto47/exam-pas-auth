import config
from utils.scores import *

text = get_pdf_as_string(config.SCORES_PDF[0])
text_cleaned = clean_results(text)
text_split_list = split_results_by_course(text_cleaned)
text_split_list = concatenate_numeros_inscricao(text_split_list)
df_scores = get_results_dataframe(text_split_list)
df_scores = rename_columns(df_scores, config.SCORES_COLUMN_NAMES)
df_scores = strip_df(df_scores)
df_scores = delete_sub_judice_students(df_scores)
df_scores = correct_course_spelling_by_fuzzywuzzy(df_scores, config.COURSE_NAMES, config.FUZZY_CONFIDENCE_THRESHOLD)
df_scores.to_parquet('../../data/interim/scores_2020_2022.parquet')
