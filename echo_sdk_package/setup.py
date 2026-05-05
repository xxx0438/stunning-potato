from setuptools import setup, find_packages

setup(
    name="echo-agent-governance",
    version="0.1.0",
    description="Official Python SDK for Echo Agent Governance",
    author="Echo",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
    ],
    python_requires=">=3.7",
)
