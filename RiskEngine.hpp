#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

struct OpportunityPayload {
    std::string url;
    std::string description;
    int domainAgeDays;
    bool hasSSL;
    bool paymentRequested;
    int scamReportCount;
    int totalReviewCount;
};

struct RiskAssessment {
    int riskScore;           // 0 (safe) to 100 (high risk scam)
    std::string status;      // VERIFIED, MIXED, or HIGH_RISK
    std::vector<std::string> flags;
};

class RiskEngine {
public:
    static RiskAssessment evaluate(const OpportunityPayload& data) {
        int score = 0;
        std::vector<std::string> detectedFlags;

        // Rule 1: SSL Check
        if (!data.hasSSL) {
            score += 25;
            detectedFlags.push_back("Missing SSL certificate (HTTP instead of HTTPS).");
        }

        // Rule 2: Domain Age Heuristic
        if (data.domainAgeDays < 30) {
            score += 35;
            detectedFlags.push_back("Domain created less than 30 days ago.");
        } else if (data.domainAgeDays < 90) {
            score += 15;
            detectedFlags.push_back("Relatively new domain (under 3 months old).");
        }

        // Rule 3: Suspicious TLD Check
        std::vector<std::string> suspiciousTLDs = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".zip"};
        for (const auto& tld : suspiciousTLDs) {
            if (data.url.length() >= tld.length() && 
                data.url.compare(data.url.length() - tld.length(), tld.length(), tld) == 0) {
                score += 20;
                detectedFlags.push_back("Uses high-risk top-level domain extension (" + tld + ").");
                break;
            }
        }

        // Rule 4: High-Risk Keyword Heuristics
        std::string lowerDesc = data.description;
        std::transform(lowerDesc.begin(), lowerDesc.end(), lowerDesc.begin(), ::tolower);

        std::vector<std::string> scamKeywords = {
            "guaranteed return", "registration fee", "no experience needed", 
            "earn $", "crypto investment", "wire transfer", "gift card"
        };

        for (const auto& kw : scamKeywords) {
            if (lowerDesc.find(kw) != std::string::npos) {
                score += 15;
                detectedFlags.push_back("Contains suspicious phrase: '" + kw + "'");
            }
        }

        // Rule 5: User Reports Ratio
        if (data.totalReviewCount > 0) {
            double reportRatio = static_cast<double>(data.scamReportCount) / data.totalReviewCount;
            if (reportRatio > 0.5) {
                score += 30;
                detectedFlags.push_back("Over 50% of user reviews flag this as a scam.");
            }
        }

        // Cap score at 100 max
        if (score > 100) score = 100;

        // Classify Status
        std::string classification;
        if (score < 30) {
            classification = "VERIFIED";
        } else if (score < 65) {
            classification = "MIXED";
        } else {
            classification = "HIGH_RISK";
        }

        return { score, classification, detectedFlags };
    }
};
