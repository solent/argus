#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>

using json = nlohmann::json;
using namespace std;

// Forward declarations of functions from utils.cpp
string processJsonData(const string& jsonString);
vector<string> extractFields(const json& data, const string& fieldName);
void displayStatistics(const vector<string>& data);
string makeHttpRequest(const string& url);
json parseAndValidateJson(const string& jsonString);

int main() {
    cout << "=== Advanced JSON Data Processor ===" << endl;
    cout << "Fetching data from JSONPlaceholder API..." << endl;
    
    // Example API endpoint
    string apiUrl = "https://jsonplaceholder.typicode.com/users";
    
    try {
        // Make HTTP request using function from utils.cpp
        string response = makeHttpRequest(apiUrl);
        
        if (response.empty()) {
            cerr << "Failed to fetch data from API" << endl;
            return 1;
        }
        
        cout << "\nData fetched successfully!" << endl;
        
        // Process the JSON data
        string processedData = processJsonData(response);
        cout << "\n=== Processed Data ===" << endl;
        cout << processedData << endl;
        
        // Parse and validate JSON
        json parsedJson = parseAndValidateJson(response);
        
        // Extract specific fields
        vector<string> names = extractFields(parsedJson, "name");
        vector<string> emails = extractFields(parsedJson, "email");
        vector<string> cities = extractFields(parsedJson, "city");
        
        // Display statistics
        cout << "\n=== User Names ===" << endl;
        displayStatistics(names);
        
        cout << "\n=== Email Domains ===" << endl;
        displayStatistics(emails);
        
        cout << "\n=== Cities ===" << endl;
        displayStatistics(cities);
        
        // Additional processing
        cout << "\n=== Summary ===" << endl;
        cout << "Total users processed: " << names.size() << endl;
        cout << "Unique cities: " << cities.size() << endl;
        
        // Interactive menu
        char choice;
        cout << "\nWould you like to fetch posts data? (y/n): ";
        cin >> choice;
        
        if (choice == 'y' || choice == 'Y') {
            string postsUrl = "https://jsonplaceholder.typicode.com/posts?_limit=5";
            string postsResponse = makeHttpRequest(postsUrl);
            
            if (!postsResponse.empty()) {
                string processedPosts = processJsonData(postsResponse);
                cout << "\n=== Recent Posts ===" << endl;
                cout << processedPosts << endl;
            }
        }
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    cout << "\n=== Processing Complete ===" << endl;
    return 0;
}
