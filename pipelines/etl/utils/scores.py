import re
from pypdf import PdfReader
import pandas as pd
import numpy as np
from fuzzywuzzy import process


def get_pdf_as_string(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    number_of_pages = len(reader.pages)

    text_list = []
    for i in range(number_of_pages):
        text_list.append(reader.pages[i].extract_text())
    
    text = ''.join(text_list)

    return text


def clean_results(text: str) -> str:
    text = re.sub(r" [0-9]+ \n", "", text)
    text = re.sub(r"\n", "", text)
    text = re.sub(r"^.*?(2\.1\.1 *)", r"\1", text)
    text = re.sub(r"\*[^*]*$", "", text)
    # cutting the end
    text = re.sub('\. \* Cursos que exigem.*', "", text)
    return text


def split_results_by_course(text: str) -> list:
    # split by course
    pattern = r'\. {1,2}(?=[A-Z]|\d\.)'
    text_split = re.split(pattern=pattern, string=text)
    return text_split


def concatenate_numeros_inscricao(text_split: list) -> list:
    # weirdly some numeros de inscricao were broken into 6 digits + blank space + 2 digits, so we unite now
    pattern = r"(\d{6})\s+(\d{2})"
    sections = [re.sub(pattern, r"\1\2", section.strip()) for section in text_split]

    pattern = r"(\d{5})\s+(\d{3})"
    sections = [re.sub(pattern, r"\1\2", section.strip()) for section in sections]

    pattern = r"(\d{7})\s+(\d{1})"
    sections = [re.sub(pattern, r"\1\2", section.strip()) for section in sections]

    return sections


def get_course_grades(my_string: str) -> tuple:
    
    pattern = "^(.*?)\d{8}, "
    result = re.search(pattern, my_string)
    
    if result:
        extracted_text = result.group(1)
        print(extracted_text)
    
    #course_dict = {}
    students = re.sub(re.escape(extracted_text), "", my_string)
    students = re.split(pattern=' /', string=students)
    
    #course_dict[extracted_text] = students

    return (extracted_text, students)


def convert_to_dataframe(my_tuple: tuple) -> pd.DataFrame:
    df = pd.Series(my_tuple[1])
    df = df.str.split(',', expand=True)
    df['course'] = my_tuple[0]
    return df


def get_results_dataframe(courses: list) -> pd.DataFrame:
    df_course = list()

    for i in range(len(courses)):
        
        course = get_course_grades(courses[i])
        course = convert_to_dataframe(course)

        df_course.append(course)
    
    scores = pd.concat(df_course)
    
    return scores


def rename_columns(df: pd.DataFrame, colnames) -> pd.DataFrame:
     df.columns = colnames
     return df


def strip_df(df: pd.DataFrame) -> pd.DataFrame:
    df['numero_inscricao'] = df['numero_inscricao'].str.replace(' ', '')
    df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)
    df.replace('-', np.nan, inplace=True)
    return df


def delete_sub_judice_students(df: pd.DataFrame) -> pd.DataFrame:
    return df[~df.course.str.contains('JUDICE|judice|candidatos')] # adding candidatos to fix urgently

  
def correct_course_spelling_by_fuzzywuzzy(
        df: pd.DataFrame,
        course_names: list,
        fuzzy_confidence_threshold: int,
) -> pd.DataFrame:

    def correct_spelling(value):
        
        corrected_value, confidence = process.extractOne(value, course_names)
        # You can adjust the confidence threshold as needed
        if confidence >= fuzzy_confidence_threshold:
            return corrected_value
        else:
            return value

    course_dict = {}
    for course in df.course.unique():
        course_dict[course] = correct_spelling(course)

    df.course = df.course.map(course_dict)

    return df
