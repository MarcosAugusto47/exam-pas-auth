import re
import pandas as pd


def delete_page_titles(text: str) -> str:
    text = re.sub(r"[0-9]* \n.*Nome.*turno", "", text)
    return text


def split_results_by_student(text: str) -> list:
    # split by student, there is a weird formattion near Ciencias Ambientais
    # so we consider that
    pattern = r'  \n(?!Ciências Ambientais|Pedagogia)'
    text_split = re.split(pattern=pattern, string=text)
    return text_split


def filtering_only_students(text_split: list) -> list:
    text_split = [text for text in text_split if re.search('[0-9]{8}', text)]
    # there are still some weird cases for students so we consider that
    text_split = [re.sub(r"\n", "", text) for text in text_split]
    return text_split


def break_list_students_info(student: str) -> pd.DataFrame:
    
    pattern = "^(.*?)\d{8} "
    result = re.search(pattern, student)
    extracted_text = result.group(0)

    student_identification = re.split('([0-9]{8})', extracted_text.strip())
    my_list = list(filter(None, student_identification))

    course_info = re.sub(re.escape(extracted_text), "", student)
    course_info = re.split(pattern=' / ', string=course_info, maxsplit=1)
    campus = course_info[0]
    course_period = course_info[1].rsplit("/", 1)
    
    my_list.append(campus)
    my_list.extend(course_period)
    
    return pd.DataFrame([my_list])


def get_approvals_dataframe(approvals: list) -> pd.DataFrame:
    
    approvals_list = list()

    for i in range(len(approvals)):
        student = break_list_students_info(approvals[i])
        approvals_list.append(student)

    df_approvals = pd.concat(approvals_list)

    return df_approvals
