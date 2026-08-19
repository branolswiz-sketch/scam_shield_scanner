#pragma once
#include <string>
#include <iostream>
#include <vector>

// Structure representing a scanned opportunity record from MySQL
struct OpportunityRecord {
    int id;
    std::string title;
    std::string url;
    std::string category;
    int domainAgeDays;
    bool hasSSL;
    int riskScore;
    std::string status;
};

class Database {
public:
    // Initialize database connection parameters
    static bool connect(const std::string& host, const std::string& user, const std::string& password, const std::string& dbName) {
        // Mock connection setup — replace with MySQL Connector / C++ driver calls
        std::cout << "[Database] Connecting to MySQL database '" << dbName << "' at " << host << "...\n";
        return true;
    }

    // Save a new URL scan result to the database
    static bool saveScanResult(const std::string& url, int riskScore, const std::string& status) {
        std::cout << "[Database] INSERT INTO opportunities (url, risk_score, status) VALUES ('"
                  << url << "', " << riskScore << ", '" << status << "');\n";
        return true;
    }

    // Retrieve previous scan details for a given URL
    static bool getOpportunityByUrl(const std::string& url, OpportunityRecord& record) {
        // Mock lookup
        record.id = 1;
        record.title = "Sample Opportunity";
        record.url = url;
        record.category = "JOB";
        record.domainAgeDays = 15;
        record.hasSSL = true;
        record.riskScore = 25;
        record.status = "VERIFIED";
        return true;
    }

    // Insert a new user scam report / flag into the queue
    static bool submitScamReport(int opportunityId, int userId, const std::string& reason, const std::string& evidenceLink) {
        std::cout << "[Database] INSERT INTO reports (opportunity_id, user_id, reason, evidence_link) VALUES ("
                  << opportunityId << ", " << userId << ", '" << reason << "', '" << evidenceLink << "');\n";
        return true;
    }
};
