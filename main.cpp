#include "crow.h"
#include "RiskEngine.hpp"

int main() {
    crow::SimpleApp app;

    // Health Check Endpoint
    CROW_ROUTE(app, "/api/health")([](){
        return crow::response(200, "ScamShield Server Active");
    });

    // Instant Scam Scan Endpoint
    CROW_ROUTE(app, "/api/scan").methods("POST"_method)([](const crow::request& req){
        auto body = crow::json::load(req.body);
        if (!body) return crow::response(400, "Invalid JSON payload");

        ScanInput input;
        input.domainAgeDays = body["domain_age"].i();
        input.hasSSL = body["has_ssl"].b();
        input.paymentReceived = body["payment_received"].b();
        input.scamReportCount = body["scam_reports"].i();
        input.totalReviews = body["total_reviews"].i();
        input.descriptionText = body["description"].s();

        // Compute Risk Score via C++ Engine
        int riskScore = RiskEngine::calculateRiskScore(input);
        std::string classification = RiskEngine::getClassification(riskScore);

        crow::json::wvalue res;
        res["url"] = body["url"].s();
        res["risk_score"] = riskScore;
        res["status"] = classification;
        
        return crow::response(200, res);
    });

    // Start server on port 18080
    app.port(18080).multithreaded().run();
}
