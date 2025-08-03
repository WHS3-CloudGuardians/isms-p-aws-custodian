from setuptools import setup, find_packages

setup(
    name="custodian_tools",
    version="0.1.0",
    packages=find_packages(),  # scripts 패키지를 포함
    entry_points={
        "console_scripts": [
            "generate = scripts.generate_policies:main",
            "enforce  = scripts.enforce_policies:main",
            "deploy   = scripts.deploy_policies:main"
        ],
    },
    install_requires=[
        "python-dotenv",
    ],
)
