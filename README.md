# ExcessivePermissionAttack
Take Over the Whole Cluster: Attacking Kubernetes via Excessive Permissions of Third-party Applications

# Code overview
This is the scan tool of our paper. For a third-party app, first, you need to install it. After that, you can run this tool and it will identify the critical component and critical daemonset of this third-party app. Note that it is still a strawman design, and we are still working on it to achieve the following: 1. Identify ALL third-party apps with potential risks automatically. 2. Leveraging the critical components of third-party apps to launch attacks automatically. Our goal is to build a tool to analyze all third-party apps and generate a PoC to launch excessive permission attacks automatically. Please feel free to contact us via issues, e-mails, or PR if you have any genius ideas or valuable comments:)

E-mail address of Nanzi Yang: nzyang@stu.xidian.edu.cn
E-mail address of Jinku Li: jkli@xidian.edu.cn

