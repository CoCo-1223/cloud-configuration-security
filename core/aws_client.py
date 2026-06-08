"""
aws_client.py
-------------
AWS에 연결하는 boto3 세션(Session)을 중앙에서 관리하는 모듈.
앱 전체에서 이 모듈을 통해 AWS 클라이언트를 생성하므로,
자격증명을 한 곳에서만 관리할 수 있습니다.
"""

import os
import boto3
from dotenv import load_dotenv

# .env 파일에서 환경 변수를 불러옵니다
load_dotenv()


def get_client(service_name: str, region: str = None):
    """
    지정한 AWS 서비스의 boto3 클라이언트를 반환합니다.

    Parameters
    ----------
    service_name : str
        AWS 서비스 이름 (예: "iam", "s3", "ec2", "cloudtrail")
    region : str, optional
        AWS 리전 (예: "ap-northeast-2"). None이면 .env의 기본값 사용.

    Returns
    -------
    boto3.client
        연결된 서비스 클라이언트 객체

    Raises
    ------
    Exception
        자격증명이 없거나 연결에 실패하면 예외를 발생시킵니다.
    """
    # 환경 변수에서 자격증명 읽기
    access_key = os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    default_region = region or os.getenv("AWS_DEFAULT_REGION", "ap-northeast-2")

    # 자격증명 존재 여부 확인
    if not access_key or not secret_key:
        raise ValueError(
            "AWS 자격증명이 없습니다. .env 파일에 "
            "AWS_ACCESS_KEY_ID와 AWS_SECRET_ACCESS_KEY를 입력해 주세요."
        )

    # boto3 클라이언트 생성 및 반환
    client = boto3.client(
        service_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=default_region,
    )
    return client


def verify_connection() -> dict:
    """
    AWS STS(Security Token Service)를 통해 연결이 정상인지 확인합니다.
    연결 성공 시 계정 ID와 IAM 사용자 ARN을 반환합니다.

    Returns
    -------
    dict
        {"success": True/False, "account_id": str, "arn": str, "error": str}
    """
    try:
        sts = get_client("sts")
        # get_caller_identity: 현재 자격증명의 계정 정보를 반환하는 API
        identity = sts.get_caller_identity()
        return {
            "success": True,
            "account_id": identity["Account"],   # AWS 계정 번호 (12자리)
            "arn": identity["Arn"],              # IAM 사용자/역할 ARN
            "error": None,
        }
    except Exception as e:
        return {
            "success": False,
            "account_id": None,
            "arn": None,
            "error": str(e),
        }
