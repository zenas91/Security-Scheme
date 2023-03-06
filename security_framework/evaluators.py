import numpy as np
import pandas as pd


def misclassified_data(model, x_test, y_test, threshold):
    pred_prob = model.predict_proba(x_test)
    thresh = []
    for i, p in enumerate(pred_prob):
        if p.max() < threshold:
            thresh.append(i)
    thresh = np.array(thresh)

    if thresh.size > 0:
        ind = y_test[thresh].astype(int)
        pred_prob[thresh, ind] = -1

    pred = np.array([np.argmax(i) for i in pred_prob])

    mask = pred == y_test
    wrong = np.array([i for i, x in enumerate(mask) if not x])

    wrongly_classified = x_test.iloc[wrong, :].copy() if isinstance(x_test, pd.DataFrame) else x_test[wrong]
    if isinstance(x_test, pd.DataFrame):
        wrongly_classified['label'] = y_test[wrong]
    else:
        wrongly_classified = np.append(wrongly_classified, y_test[wrong].reshape([-1, 1]), axis=1)
    return wrongly_classified

