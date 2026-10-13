# Machine Learning for Network Intrusion Detection

## Overview

This project focuses on the design, implementation, and evaluation of a machine learning model for detecting cyberattacks in network traffic. The proposed solution combines a **Random Forest classifier with a neural network** to distinguish between benign and malicious network activity.

A key objective was to evaluate the model not only on familiar data but also on a different dataset containing previously unseen attack types.

## Technologies & Methods

- **Machine Learning:** Random Forest, Neural Networks
- **Datasets:** CIC-IDS2017, CIC-IDS2018
- **Network Security:** Zeek IDS
- **Model Optimization:** Neural network architecture, voting weights, number of trees
- **Evaluation:** Cross-dataset testing and comparison with a traditional intrusion detection system

## Approach

1. Trained and optimized a hybrid model combining Random Forest and a neural network using CIC-IDS2017.
2. Evaluated the model on CIC-IDS2018 to investigate its ability to detect attacks outside the original training data.
3. Compared its detection capabilities with the traditional Zeek intrusion detection system.
4. Investigated challenges related to network traffic preprocessing, flow extraction, and generalization to unseen data.

## Key Findings

- Achieved high classification accuracy during validation on CIC-IDS2017.
- Detected a significant number of attacks that were not identified by Zeek during cross-dataset testing.
- Demonstrated the potential of machine learning to complement traditional intrusion detection systems.
- Identified a trade-off between higher attack sensitivity and an increased number of false positives.

## Limitations & Future Work

The main challenges included differences in network flow extraction tools, limited dataset diversity, and the gap between laboratory datasets and real-world network traffic.

Potential improvements include expanding the training data, standardizing preprocessing, further hyperparameter optimization, and exploring more advanced neural network architectures such as LSTM or CNN.

## Academic Context

Developed as part of a bachelor's thesis focused on applying machine learning to cybersecurity and evaluating its practical potential for network intrusion detection.
