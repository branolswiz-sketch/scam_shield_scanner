#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

struct ScanInput {
    int domainAgeDays;
    bool hasSSL;
    bool paymentReceived;
    int scamReportCount;
    int totalReviews;
    bool adminVerified;
    std::string descriptionText;
};

class RiskEngine {
public:
    static int calculateRiskScore(const ScanInput& input) {
        double score = 0.0;

        // 1. User Reviews & Community Reports (40% Weight)
        if (input.totalReviews > 0) {
            double scamRatio = static_cast<double>(input.scamReportCount) / input.totalReviews;
            score += (scamRatio * 40.0);
        }

        // 2. Domain Age (20% Weight)
        if (input.domainAgeDays < 14) {
            score += 20.0; // Brand new domain
        } else if (input.domainAgeDays < 90) {
            score += 10.0; // Moderately new domain
        }

        // 3. Payment History Verification (20% Weight)
        if (!input.paymentReceived) {
            score += 20.0; // Non-payment reported
        }

        // 4. Keyword Heuristics Detection (10% Weight)
        int keywordCount = checkKeywords(input.descriptionText);
        if (keywordCount >= 3) {
            score += 10.0;
        } else if (keywordCount > 0) {
            score += 5.0;
        }

        // 5. SSL & Security Checks (10% Weight)
        if (!input.hasSSL) {
            score += 10.0;
        }

        int finalScore = static_cast<int>(score);
        return std::min(finalScore, 100);
    }

    static std::string getClassification(int riskScore) {
        if (riskScore <= 30) return "VERIFIED";
        if (riskScore <= 60) return "MIXED";
        return "SCAM";
    }

private:
    static int checkKeywords(std::string text) {
        std::transform(text.begin(), text.end(), text.begin(), ::tolower);
        std::vector<std::string> redFlags = {
            "guaranteed income",
            "double your money",
            "registration fee required",
            "no skills needed",
            "earn 10,000 per day",
            "invest and relax",
            "login-verify"
        };

        int matches = 0;
        for (const auto& kw : redFlags) {
            if (text.find(kw) != std::string::npos) {
                matches++;
            }
        }
        return matches;
    }
};
