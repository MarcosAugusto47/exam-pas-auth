import config
from utils.scores import get_pdf_as_string, rename_columns
from utils.labels_convocation import *


def label_convocation_wrapper(approvals_file_path):
    text = get_pdf_as_string(approvals_file_path)
    text_cleaned = clean_text(text)
    text_split_list = split_by_course(text_cleaned)
    #text_split_list_students = filtering_only_students(text_split_list)
    df_approvals = get_approvals_dataframe(text_split_list)
    df_approvals = rename_columns(df_approvals, config.CONVOCATIONS_COLUMNS_NAMES)
    
    return df_approvals


def main():

    df_2020_2022 = pd.concat([label_convocation_wrapper(config.CONVOCATIONS_FILES[0]),
                              label_convocation_wrapper(config.CONVOCATIONS_FILES[1])])
    df_2020_2022.to_parquet('../../data/interim/approvals_convocation_2020_2022.parquet')

    df_2019_2021 = pd.concat([label_convocation_wrapper(config.CONVOCATIONS_FILES[2]),
                              label_convocation_wrapper(config.CONVOCATIONS_FILES[3])])
    df_2019_2021.to_parquet('../../data/interim/approvals_convocation_2019_2021.parquet')


if __name__ == '__main__':
    main()
