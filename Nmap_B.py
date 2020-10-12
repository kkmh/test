__author__ = 'kkkkkkk'

# -*-coding:utf-8-*-
# Library


import shutil
import os
import logging

file = open("policy.txt", "r")
policy = file.read().split()

# 정책 파일  #



print("[1] Default Scan(Default Policy:기본정책) \n")
print("[2] Custom Scan(Detail Policy사용자 설정 정책) \n")
# 스캔 정책 결정
option0 = input(" 스캔 옵션 선택 (숫자입력 1 or 2): ")

print()
if option0 == '1':
    # 기본

    print("[1] single IP ex : 192.0.0.1    \n")
    print("[2] IP Range : 192.0.0.X    \n")

    option1 = input("Choose 2nd option(숫자입력 1 or 2 ): ")

    if option1 == '1':
        sIP = input("단일 IP 입력 (예:192.168.0.1): \n")

        nmap_command = policy[0] + " " + sIP

        print("scanIP : ", nmap_command)

        os.system(nmap_command)

        if not os.path.exists(sIP):

            os.makedirs(sIP)  # IP 별 폴더 생성

            nmap_xml = sIP + ".xml"  # 파일확장자 설정

            nmap_nmap = sIP + ".nmap"

            nmap_gnmap = sIP + ".gnmap"

            target_dir = sIP

            try:

                shutil.move(nmap_gnmap, target_dir)

                shutil.move(nmap_nmap, target_dir)

                shutil.move(nmap_xml, target_dir)

            except:

                pass



    elif option1 == '2':

        rIP1 = input("IP Range 입력 (예:192.168.0.x): \n")

        rIP = rIP1.replace("x", "0/24")

        nmap_command = policy[0] + " " + rIP

        print("scanIP : ", nmap_command)

        os.system(nmap_command)

        if not os.path.exists(rIP):

            os.makedirs(rIP)  # IP 별 폴더 생성

            nmap_xml = rIP + ".xml"  # 파일확장자 설정

            nmap_nmap = rIP + ".nmap"

            nmap_gnmap = rIP + ".gnmap"

            target_dir = rIP

            try:

                shutil.move(nmap_gnmap, target_dir)

                shutil.move(nmap_nmap, target_dir)

                shutil.move(nmap_xml, target_dir)

            except:

                pass
    else:
        print('Your Choice is Invalid')


elif option0 == '2':
    # custom 정책 추가


    print("[1] single IP ex : 192.0.0.1    \n")
    print("[2] IP Range : 192.0.0.X    \n")

    option1 = input(" 옵션 선택 (숫자 1 or 2입력):  \n")

    if option1 == '1':

        sIP = input(" 단일 IP 입력 (예:192.168.0.1): \n")

        nmap_command = policy[1] + " " + sIP

        print("scanIP : ", nmap_command)

        os.system(nmap_command)

        if not os.path.exists(sIP):

            os.makedirs(sIP)  # IP 별 폴더 생성

            nmap_xml = sIP + ".xml"  # 파일확장자 설정

            nmap_nmap = sIP + ".nmap"

            nmap_gnmap = sIP + ".gnmap"

            target_dir = sIP

            try:

                shutil.move(nmap_gnmap, target_dir)

                shutil.move(nmap_nmap, target_dir)

                shutil.move(nmap_xml, target_dir)

            except:

                pass



    elif option1 == '2':

        rIP1 = input("IP Range 입력 (예:192.168.0.x):  \n")

        rIP = rIP1.replace("x", "0/24")

        nmap_command = policy[1] + " " + sIP

        print("scanIP : ", nmap_command)

        os.system(nmap_command)

        if not os.path.exists(rIP):

            os.makedirs(rIP)  # IP 별 폴더 생성

            nmap_xml = rIP + ".xml"  # 파일확장자 설정

            nmap_nmap = rIP + ".nmap"

            nmap_gnmap = rIP + ".gnmap"

            target_dir = rIP

            try:

                shutil.move(nmap_gnmap, target_dir)

                shutil.move(nmap_nmap, target_dir)

                shutil.move(nmap_xml, target_dir)

            except:

                pass
    else:
        print('Your Choice is Invalid')


else:
    print('Your Choice is Invalid')
