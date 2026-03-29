#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>

using json = nlohmann::json;
using namespace std;

// Make an HTTP GET request and return the response body
string makeHttpRequest(const string& url) {
    try {
        cpr::Response r = cpr::Get(cpr::Url{url},
                                   cpr::Timeout{10000});
        
        if (r.status_code == 200) {
            return r.text;
        } else {
            cerr << "HTTP Error: " << r.status_code << endl;
            return "";
        }
    } catch (const exception& e) {
        cerr << "Request failed: " << e.what() << endl;
        return "";
    }
}

// Parse and validate JSON string
json parseAndValidateJson(const string& jsonString) {
    try {
        json parsed = json::parse(jsonString);
        
        if (parsed.is_null()) {
            throw runtime_error("Parsed JSON is null");
        }
        
        return parsed;
    } catch (const json::parse_error& e) {
        throw runtime_error(string("JSON parsing error: ") + e.what());
    }
}

// Process JSON data and return formatted string
string processJsonData(const string& jsonString) {
    stringstream result;
    
    try {
        json data = parseAndValidateJson(jsonString);
        
        if (data.is_array()) {
            result << "Array with " << data.size() << " elements" << endl;
            result << "-----------------------------------" << endl;
            
            int count = 0;
            for (const auto& item : data) {
                count++;
                result << "Item " << count << ":" << endl;
                
                // Display key information
                if (item.contains("id")) {
                    result << "  ID: " << item["id"] << endl;
                }
                if (item.contains("name")) {
                    result << "  Name: " << item["name"] << endl;
                }
                if (item.contains("title")) {
                    result << "  Title: " << item["title"] << endl;
                }
                if (item.contains("email")) {
                    result << "  Email: " << item["email"] << endl;
                }
                
                // Handle nested objects
                if (item.contains("address") && item["address"].is_object()) {
                    result << "  City: " << item["address"]["city"] << endl;
                }
                
                result << endl;
                
                if (count >= 10) break; // Limit output
            }
        } else if (data.is_object()) {
            result << "Single object:" << endl;
            result << data.dump(2) << endl;
        }
        
    } catch (const exception& e) {
        result << "Error processing JSON: " << e.what() << endl;
    }
    
    return result.str();
}

// Extract specific fields from JSON array
vector<string> extractFields(const json& data, const string& fieldName) {
    vector<string> results;
    
    try {
        if (data.is_array()) {
            for (const auto& item : data) {
                if (item.contains(fieldName)) {
                    results.push_back(item[fieldName].get<string>());
                } else if (item.contains("address") && 
                          item["address"].is_object() && 
                          item["address"].contains(fieldName)) {
                    // Handle nested fields in address
                    results.push_back(item["address"][fieldName].get<string>());
                }
            }
        }
    } catch (const exception& e) {
        cerr << "Error extracting field '" << fieldName << "': " << e.what() << endl;
    }
    
    return results;
}

// Display statistics about the data
void displayStatistics(const vector<string>& data) {
    if (data.empty()) {
        cout << "No data to display" << endl;
        return;
    }
    
    // Count occurrences
    map<string, int> frequency;
    for (const auto& item : data) {
        frequency[item]++;
    }
    
    // Sort by frequency
    vector<pair<string, int>> sortedFreq(frequency.begin(), frequency.end());
    sort(sortedFreq.begin(), sortedFreq.end(),
         [](const pair<string, int>& a, const pair<string, int>& b) {
             return a.second > b.second;
         });
    
    // Display results
    cout << "Total entries: " << data.size() << endl;
    cout << "Unique entries: " << frequency.size() << endl;
    cout << "\nTop entries:" << endl;
    
    int displayCount = min(5, static_cast<int>(sortedFreq.size()));
    for (int i = 0; i < displayCount; i++) {
        cout << "  " << setw(30) << left << sortedFreq[i].first 
             << " (count: " << sortedFreq[i].second << ")" << endl;
    }
}
