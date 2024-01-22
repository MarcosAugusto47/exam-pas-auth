FEATURES = ['escore_bruto_p1_etapa1',
            'escore_bruto_p2_etapa1',
            #'nota_redacao_etapa1',
            'escore_bruto_p1_etapa2',
            'escore_bruto_p2_etapa2',
            #'nota_redacao_etapa2',
            'escore_bruto_p1_etapa3',
            'escore_bruto_p2_etapa3',
            #'nota_redacao_etapa3',
            'pseudo_argumento_final',
            'min_flag',
            'median_flag',
            #'dist_max',
            #'dist_mean',
            #'cotista',
            'cotas_negros_flag',
            #'publicas_flag',
            'publicas1_flag',
            'publicas2_flag',
            'publicas3_flag',
            'publicas4_flag',
            'publicas5_flag',
            'publicas6_flag',
            'publicas7_flag',
            'publicas8_flag',
            'course']

HYPERPARAMETERS = {
    'booster': 'gbtree',
    'tree_method': 'hist',
    #'max_bin': 300,
    'n_estimators': 350,
    'eta': 0.1,                        # Learning rate
    'max_depth': 8,                   # Maximum depth of a tree
    'subsample': 0.7,                  # Subsample ratio of the training instances
    #'colsample_bytree': 0.8,          # Subsample ratio of columns when constructing each tree
    #'scale_pos_weight': class_ratio,
    'scale_pos_weight': 2,
    'gamma': 5,
    'lambda': 3}

# constraints from features escore_bruto_p1_etapa1 to cotas_negros_flag
MONOTONE_CONSTRAINTS = '(1, 1, 1, 1, 1, 1, 1, 1, 1, 1)'