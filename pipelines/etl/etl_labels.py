import config
from utils.scores import get_pdf_as_string, rename_columns
from utils.labels import *

print(config.APPROVALS_PDF) 

def label_wrapper(approvals_file_path):
    text = get_pdf_as_string(approvals_file_path)
    text_cleaned = delete_page_titles(text)
    text_split_list = split_results_by_student(text_cleaned)
    text_split_list_students = filtering_only_students(text_split_list)
    df_approvals = get_approvals_dataframe(text_split_list_students)
    df_approvals = rename_columns(df_approvals, config.APPROVALS_COLUMNS_NAMES)
    return df_approvals

df_2020_2022 = pd.concat([label_wrapper(config.APPROVALS_PDF[0]), label_wrapper(config.APPROVALS_PDF[1])])
df_2020_2022.to_parquet('../../data/interim/approvals_2020_2022_complete.parquet')

df_2019_2021 = pd.concat([label_wrapper(config.APPROVALS_PDF[2]), label_wrapper(config.APPROVALS_PDF[3])])
df_2019_2021.to_parquet('../../data/interim/approvals_2019_2021_complete.parquet')

#df_2018_2020 = label_wrapper(config.APPROVALS_PDF[3])
#df_2018_2020.to_parquet('../../data/interim/approvals_2018_2020.parquet')
