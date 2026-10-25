import sys, csv
DATASET = 'dataset'

with open(f'{DATASET}/system_activity.csv', newline='') as f:
    acts = list(csv.DictReader(f))

# Check account_001-010 deletions
targets = ['account_001','account_002','account_003','account_004','account_005',
           'account_006','account_007','account_008','account_009','account_010']
for t in targets:
    rows = [a for a in acts if a['resource_id']==t and a['event_type']=='DELETE_RECORD']
    if rows:
        r = rows[-1]
        print(t, r['event_time'], r['reported_result'], r['details'][:80])
    else:
        print(t, "no DELETE")

print("---")
# Show all activities for amina/user_01
with open(f'{DATASET}/user_identities.csv', newline='') as f:
    users = {r['email'].lower(): r for r in csv.DictReader(f)}
u = users.get('amina.elmasri@gmail.com', {})
uid = u.get('user_id','')
print("amina user_id:", uid)
# find activities that mention user_01 numerically
import re
for a in acts:
    rid = a['resource_id']
    n = re.sub(r'\D', '', rid)
    if n == '1' or n == '01':
        print(a['activity_id'], a['event_type'], a['resource_id'], a['event_time'])
