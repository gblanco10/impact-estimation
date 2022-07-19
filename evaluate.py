import json
import os
import pandas as pd
import argparse

from sklearn.metrics import precision_recall_fscore_support,mean_absolute_percentage_error,mean_absolute_error,mean_squared_error,accuracy_score, f1_score

from impact_estimation.constants import infrastructure_category,population_category



def get_base_prediction():
    base_estimate_pred = {}
    for cat in infrastructure_category+population_category:
        base_estimate_pred[cat] = 0
        base_estimate_pred[cat+"_est"] = 0
    return base_estimate_pred

def get_predictions_df(input_path:str,get_map=False):
    with open(input_path,encoding='utf-8') as f:
        tweets = json.load(f)
    tweets_pred = []
    ids=[]
    for tweet in tweets:
        base_pred = get_base_prediction()
        ids.append(tweet['tweet_id'])
        base_pred['event_id'] = tweet['event_id']
        for category in tweet['impact'].keys():
            for rule,est in tweet['impact'][category].items():
                base_pred[rule]=1
                base_pred[rule+"_est"]=est 
        tweets_pred.append(base_pred)
    df= pd.DataFrame(tweets_pred,index=ids)
    if not get_map:
        return df.sort_index(ascending=True)
    else:
        id2tweet = {t['tweet_id']:t for t in tweets}
        return df.sort_index(ascending=True),id2tweet

def get_mistakes(tweet_ids,gt_mapid,pred_mapid):
    tweets=[]
    for id in tweet_ids:
        tweet = pred_mapid[id]
        tweet['impact_gt'] = gt_mapid[id]['impact']
        tweets.append(tweet)
    return tweets

def get_classification_metrics(gt,pred,merge):
    metrics_result = []
    for cat in infrastructure_category+population_category:
        prec,rec,f1,_ = precision_recall_fscore_support(gt[cat].values,pred[cat].values,average='binary',pos_label=1,zero_division=0)
        supp = sum(gt[cat] == 1)
        fp_mask = (merge[cat+'_pred'] == 1) & (merge[cat+'_gt'] == 0)
        fp_tweets = get_mistakes(merge.loc[fp_mask].index.values,id2tweet_gt,id2tweet_pred)
        fn_mask = (merge[cat+'_pred'] == 0) & (merge[cat+'_gt'] == 1)
        fn_tweets = get_mistakes(merge.loc[fn_mask].index.values,id2tweet_gt,id2tweet_pred)
        out = os.path.join(args.OUT_PATH,cat)
        if not os.path.isdir(out):
            os.mkdir(out)
        with open(os.path.join(out,'fp.json'),'w',encoding='utf-8') as f:
            json.dump(fp_tweets,f,indent=3)
        with open(os.path.join(out,'fn.json'),'w',encoding='utf-8') as f:
            json.dump(fn_tweets,f,indent=3)
        metrics_result.append({'accuracy':accuracy_score(gt[cat].values,pred[cat].values),'precision':prec,'recall':rec,'f1-score':f1,'support':supp})
    return pd.DataFrame(metrics_result,index=infrastructure_category+population_category)

def get_regression_metrics(gt, pred, support_only=True,exclude_zero=False):
    metrics_result = []
    metrics = []
    for cat in infrastructure_category+population_category:
        supporting_indexes_mask = gt[cat] == 1
        if support_only:
            true_values = gt.loc[supporting_indexes_mask][cat+'_est']
            pred_values = pred.loc[supporting_indexes_mask][cat+'_est']
        else:
            true_values = gt[cat+'_est']
            pred_values = pred[cat+'_est']
        if exclude_zero:
            non_zero_mask = true_values != 0
            true_values=true_values.loc[non_zero_mask]
            pred_values=pred_values.loc[non_zero_mask]
        if true_values.shape[0] == 0:continue
        metrics.append(cat)
        metrics_result.append({
            'mape': mean_absolute_percentage_error(true_values, pred_values),
            'mae': mean_absolute_error(true_values, pred_values),
            'mse':mean_squared_error(true_values,pred_values), 
            'support': true_values.shape[0]})
    return pd.DataFrame(metrics_result, index=metrics)

def store_errors(merge):
    for cat in infrastructure_category+population_category:
        df = merge.loc[(merge[f'{cat}_gt'] == 1) & (merge[f'{cat}_est_gt'] != merge[f'{cat}_est_pred'])]
        # print(df)
        # break
        tweets = get_mistakes(df.index.values,id2tweet_gt,id2tweet_pred)
        with open(os.path.join(args.OUT_PATH,cat,'errors.json'),'w',encoding='utf-8') as f:
            json.dump(tweets,f,indent=4)
    return

parser = argparse.ArgumentParser()


parser.add_argument(
    '--pred', help='Path of tweets predictions', type=str, required=True,dest='PRED_PATH')
parser.add_argument(
    '--gt', help='Path of tweets predictions ground truth', type=str, required=True,dest='GT_PATH')

parser.add_argument('--event',action='store_true',help='If specified, the script will evaluate metrics per event type',dest='EVENT')
parser.add_argument('--overall',action='store_true',help='If specified, the script will evaluate overall metrics',dest='OVERALL')

parser.add_argument('--out',help='Output path where metrics are stored',type=str,required=True,dest='OUT_PATH')

args = parser.parse_args()

if not os.path.exists(args.PRED_PATH):
    exit(f"{args.PRED_PATH} does not exists")

if not os.path.exists(args.GT_PATH):
    exit(f"{args.GT_PATH} does not exists")

if not os.path.isdir(args.OUT_PATH):
    os.makedirs(args.OUT_PATH,exist_ok=True)

print("Reading predictions file..")
pred_df,id2tweet_pred = get_predictions_df(args.PRED_PATH,get_map=True)
print(f"Found {pred_df.shape[0]} tweets in predictions file")

print("Reading ground truth file..")
gt_df,id2tweet_gt = get_predictions_df(args.GT_PATH,get_map=True)
print(f"Found {gt_df.shape[0]} tweets in ground truth file")

print("Checking correctness..")

assert gt_df.shape[0] == pred_df.shape[0]
assert all(pred_df.index.values ==  gt_df.index.values)


print("Storing predictions data...")
gt_df.to_csv(os.path.join(args.OUT_PATH,'ground_truth.csv'),sep='\t')
pred_df.to_csv(os.path.join(args.OUT_PATH,'predictions.csv'),sep='\t')

merge_df = pred_df.merge(gt_df,how='outer',left_index=True,right_index=True,suffixes=['_pred','_gt'])

print("Evaluating classification metrics....")

classification_df = get_classification_metrics(gt_df,pred_df,merge_df)
classification_df.to_csv(os.path.join(args.OUT_PATH,'class_metrics.csv'),sep='\t')

print("Evaluating regression metrics...")
regression_df = get_regression_metrics(gt_df,pred_df,support_only=False)
regression_df.to_csv(os.path.join(args.OUT_PATH,'regression_metrics.csv'),sep='\t')

supported_regression_df = get_regression_metrics(gt_df,pred_df,support_only=True)
supported_regression_df.to_csv(os.path.join(args.OUT_PATH,'supported_regression_metrics.csv'),sep='\t')

supported_nonzero_regression_df = get_regression_metrics(gt_df,pred_df,support_only=True,exclude_zero=True)
supported_nonzero_regression_df.to_csv(os.path.join(args.OUT_PATH,'supported_nonzero_regression_metrics.csv'),sep='\t')

store_errors(merge_df)

if args.OVERALL:
    print("Evaluating overall metrics...")
    acc= accuracy_score(gt_df[infrastructure_category+population_category].values,pred_df[infrastructure_category+population_category].values)
    # f1= f1_score(gt_df[infrastructure_category+population_category].values,pred_df[infrastructure_category+population_category].values,average='samples')
    # p= accuracy_score(gt_df[infrastructure_category+population_category].values,pred_df[infrastructure_category+population_category].values)
    # r= accuracy_score(gt_df[infrastructure_category+population_category].values,pred_df[infrastructure_category+population_category].values)
    p,r,f1,_ = precision_recall_fscore_support(gt_df[infrastructure_category+population_category].values,pred_df[infrastructure_category+population_category].values,average='samples')
    column_names = [f"{cat}_est" for cat in infrastructure_category+population_category]
    mae = mean_absolute_error(gt_df[column_names].values,pred_df[column_names].values)
    mse = mean_squared_error(gt_df[column_names].values,pred_df[column_names].values)
    print(f"F1 score: {f1}")
    print(f"Precision: {p}")
    print(f"Recall: {r}")
    print(f"Accuracy score: {acc}")
    print(f"MAE score: {mae}")
    print(f"MSE score: {mse}")
    overall_df = pd.DataFrame([f1,acc,p,r,mae,mse],index=['f1','acc','p','r','mae','mse'])
    overall_df.to_csv(os.path.join(args.OUT_PATH,'overall_metrics.csv'),sep='\t')

if args.EVENT : 
    print("Evaluating metrics per event type...")
    EVENT_TYPE = {
        'storm' : [24225],
        'fire' : [44113],
        'earthquake':[20498],
        'flood':[22859, 31590, 42372]
    }
    for event_type, event_ids in EVENT_TYPE.items():
        gt_event = gt_df.loc[gt_df['event_id'].isin(event_ids)]
        pred_event = pred_df.loc[pred_df['event_id'].isin(event_ids)]
        merge_event = pred_event.merge(gt_event,how='outer',left_index=True,right_index=True,suffixes=['_pred','_gt'])
        
        os.makedirs(os.path.join(args.OUT_PATH,'cls_event_metrics'),exist_ok=True)
        classification_df = get_classification_metrics(gt_event,pred_event,merge_event)
        classification_df.to_csv(os.path.join(args.OUT_PATH,'cls_event_metrics',f'{event_type}_class_metrics.csv'),sep='\t')
        
        os.makedirs(os.path.join(args.OUT_PATH,'regression_event_metrics'),exist_ok=True)
        supported_regression_event = get_regression_metrics(gt_event,pred_event,support_only=True)
        supported_regression_event.to_csv(os.path.join(args.OUT_PATH,'regression_event_metrics',f'{event_type}_supported_regression_metrics.csv'),sep='\t')


print("Done.")