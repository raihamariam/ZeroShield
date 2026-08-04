"""Milestone 21: RabbitMQ consumer that executes queued experiment-run jobs.

A thin process only - see processor.py for the (broker-independent, directly
testable) job-processing logic and services.experiment_service for the
actual execution. No safety, strategy, orchestration, or metric logic is
implemented in this package.
"""
