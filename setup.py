from setuptools import find_packages, setup

setup(
    name="cloudsec-scanner",
    version="0.1.0",
    description="Multi-cloud security posture scanner (AWS/Azure/GCP)",
    packages=find_packages(exclude=["tests*"]),
    install_requires=["boto3>=1.34", "click>=8.1"],
    extras_require={
        "azure": ["azure-identity>=1.15", "azure-mgmt-storage>=21.1", "azure-mgmt-network>=25.3"],
        "gcp": ["google-cloud-storage>=2.14", "google-cloud-compute>=1.16"],
    },
    entry_points={
        "console_scripts": [
            "cloudsec-scanner=cloudsec_scanner.cli:main",
        ],
    },
    python_requires=">=3.9",
)
