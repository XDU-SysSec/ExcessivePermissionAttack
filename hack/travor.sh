kubectl create clusterrole travor--pod--list --verb=list --resource=pods
kubectl create clusterrole travor--clusterrolebind--list --verb=list --resource=clusterrolebindings
kubectl create clusterrole travor--rolebind--list --verb=list --resource=rolebindings
#kubectl create clusterrole travor-sa-get --verb=get --resource=serviceaccounts
kubectl create clusterrole travor-clusterrole-get --verb=get --resource=clusterroles
kubectl create clusterrole travor-role-get --verb=get --resource=roles
kubectl create clusterrole travor-node-list --verb=list --resource=nodes
kubectl create clusterrole travor--pod--get --verb=get --resource=pods


kubectl create clusterrolebinding travor--pod--list --clusterrole=travor--pod--list --serviceaccount=default:travor
kubectl create clusterrolebinding travor--clusterrolebind--list --clusterrole=travor--clusterrolebind--list --serviceaccount=default:travor
kubectl create clusterrolebinding travor--rolebind--list --clusterrole=travor--rolebind--list --serviceaccount=default:travor
#kubectl create clusterrolebinding travor-sa-get --clusterrole=travor-sa-get --serviceaccount=default:travor
kubectl create clusterrolebinding travor-clusterrole-get --clusterrole=travor-clusterrole-get --serviceaccount=default:travor
kubectl create clusterrolebinding travor-role-get --clusterrole=travor-role-get --serviceaccount=default:travor
kubectl create clusterrolebinding travor-node-list --clusterrole=travor-node-list --serviceaccount=default:travor
kubectl create clusterrolebinding travor--pod--get --clusterrole=travor--pod--get --serviceaccount=default:travor
