import pandas as pd
import re


def clean_text(text: str) -> str:
    text = re.sub(r"N.*\n.*Nome.*subsistema", "", text)
    text = re.sub(r"[0-9]{1}\.[0-9]{1}\.[0-9]+.*\n", "", text)
    text = re.sub(r"[0-9]+ (\n )", r"\n", text)
    # remove double white spaces only if they are surrounded by letters in a string
    text = re.sub(r'(?<=[a-zA-Z]) {2}(?=[a-zA-Z])', ' ', text)
    text = re.sub(r"\n\* Cursos que exigem.*", "", text, flags=re.DOTALL)

    return text


def split_by_course(text: str) -> list:
    pattern = r'(?=\n[A-Z]{1}.*\s)'
    text_split = re.split(pattern=pattern, string=text)
    text_split = [text for text in text_split if re.search('[0-9]{8}', text)]
    text_split = [re.sub(r"\n", "", text) for text in text_split]

    return text_split


def get_approvals_by_course(course_approvals: str) -> pd.DataFrame:
    pattern = r'(?=[0-9]{8})'
    course_segment = re.split(pattern=pattern, string=course_approvals)
    course_segment = [x.strip() for x in course_segment]

    df_course = pd.Series(course_segment[1:]).str.split('  ', expand=True)
    df_course['course'] = course_segment[0]

    return df_course


def get_approvals_dataframe(approvals: list) -> pd.DataFrame:
    
    approvals_list = list()

    for i in range(len(approvals)):
        student = get_approvals_by_course(approvals[i])
        approvals_list.append(student)

    df_approvals = pd.concat(approvals_list)

    return df_approvals
