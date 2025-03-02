/*
    Copyright (C) 2025 n0m1x

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Data Pipelines
// file -> buffer_in_parent  -> buffer_in_ipc  -> buffer_in_child
// file <- buffer_out_parent <- buffer_out_ipc <- process

#define BUFFER_OUT_IPC_SIZE 32
#define BUFFER_IN_CHILD_SIZE 1024
#define BUFFER_IN_IPC_SIZE BUFFER_IN_CHILD_SIZE * 2

#define MAX_LOGIN_LEN 512  // Maximum length of a username:password pair
using char_array_logins = std::array<char, MAX_LOGIN_LEN>;

namespace fs = std::filesystem;
#define SEM_NAME "/loginclear_semaphore"
#define DEFAULT_NUM_PROC 4


// +++ Structs +++

struct ParamStruct {
    std::string request_file;           // -r
    std::string users_file;             // -u
    std::string passwords_file;         // -p
    std::string domain;                 // -d
    std::vector<std::string> regex_patterns;   // -n
    std::vector<std::string> string_patterns;  // -N
    bool invert_pattern = false;        // -i [optional]
    int request_delay = 0;              // -w [optional]
    int num_proc = DEFAULT_NUM_PROC;    // -t [optional]
    std::string pot_file;               // -o [optional]
    bool verbose = false;               // -v [optional]
    std::string ignore_http_status_codes = "400-599";  // -c [optional]
};

struct IpcStruct {
    struct StatusData {
        long total_requests = 1;
        int total_retries = 0;
        std::array<char, MAX_LOGIN_LEN> current_login;
        double total_gb_received = 0.0;
        double total_gb_sent = 0.0;
        double total_response_time = 0.0;
    } status;
    int fail_counter = 0;

    // Flag set by parent if login buffer empty
    bool no_more_logins = false;

    // I/O Buffers
    std::array<char_array_logins, BUFFER_IN_IPC_SIZE> buffer_in_ipc;
    std::array<char_array_logins, BUFFER_OUT_IPC_SIZE> buffer_out_ipc;
};

struct CallbackParam {
    bool match = false;
    size_t total_received = 0;
    std::string response_data = "";
};


// +++ Curl Callback +++

// Custom callback function to check if the response contains a specific string
size_t writer_callback(void *contents, size_t size, size_t nmemb, CallbackParam *callback_param) {
    size_t total_size = size * nmemb;
    callback_param->total_received += total_size;
    std::string response(static_cast<char*>(contents), size * nmemb);
    callback_param->response_data += response;

    // Return the actual number of bytes processed (size * nmemb)
    // This is required by cURL to continue processing
    return total_size;
}


// +++ IPC +++

// Sleep for a specified duration (i2 == 0) or a random duration (i1 < i2) of milliseconds
void sleep_chrono(int i1, int i2) {
    if (i2 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(i1));
        return;
    }

    // Ensure i1 is lower than i2
    if (i1 >= i2) {
        std::cerr << "Error: i1 must be lower than i2." << std::endl;
        return;
    }

    // Seed random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(i1, i2);

    // Generate random number between i1 and i2
    int random_wait = dist(gen);

    // Sleep for the random number of milliseconds
    std::this_thread::sleep_for(std::chrono::milliseconds(random_wait));
}

// Check if the buffer is completely empty
bool is_buffer_empty(std::array<char_array_logins, BUFFER_IN_IPC_SIZE>& buffer) {
    for (const auto& item : buffer) {
        if (item[0] != '\0') {
            return false;
        }
    }
    return true;
}


// +++ CLI Parameters +++

void print_help() {
    std::cout << "SYNOPSIS" << std::endl;
    std::cout << "loginclear -r <file> -u <file> -p <file> -d <url> { -n <regexp> | -N <string> } [OPTIONS]" << std::endl;
    std::cout << std::endl;
    std::cout << "DESCRIPTION" << std::endl;
    std::cout << "Loginclear is a brute forcing tool for web logins." << std::endl;
    std::cout << std::endl;
    std::cout << "OPTIONS" << std::endl;
    std::cout << "  -r <file>     : HTTP login request template" << std::endl;
    std::cout << "  -u <file>     : Users file" << std::endl;
    std::cout << "  -p <file>     : Passwords file" << std::endl;
    std::cout << "  -d <url>      : Target URL (format: http[s]://<ip/domain>[:port])" << std::endl;
    std::cout << "  -n <regex>    : Regular expression to detect successful logins (e.g., -n \"HTTP\\/1\\.. 302 Found\")" << std::endl;
    std::cout << "  -N <string>   : Simple text string to detect successful logins (e.g., -N \"Login successful\")" << std::endl;
    std::cout << "  -i            : Inverted pattern matching: if none of the patterns are found, the response is treated as successful login" << std::endl;
    std::cout << "  -w <int>      : Optional delay in milliseconds (Default: 0)" << std::endl;
    std::cout << "  -t <int>      : Number of processes (Default: " << DEFAULT_NUM_PROC << ")" << std::endl;
    std::cout << "  -o <file>     : Pot file for saving successful candidates (optional)" << std::endl;
    std::cout << "  -c <range>    : Ignore responses by HTTP status code (e.g., -n 101,102,200-300 default: 400-599)" << std::endl;
    std::cout << "  -v            : Enable verbose output" << std::endl;
    std::cout << "  -h            : Print help" << std::endl;
    std::cout << std::endl;
    std::cout << "INFO" << std::endl;
    std::cout << " - If the request file only contains one of the two payload fields only one of -u and -p is required." << std::endl;
    std::cout << " - HTTP headers are included in the response, and patterns are searched there too." << std::endl;
    std::cout << " - The following payload fields can be specified in the request file: ^USER^, ^PASSWORD^, ^e(USER)^, ^e(PASSWORD)^." << std::endl;
    std::cout << " - The e() function URL encodes all special characters of the payload string, except for the characters *-._." << std::endl;
}

// Validate regex patterns
bool validate_regex(const std::string& pattern) {
    try {
        std::regex regex_pattern(pattern);
    } catch (const std::regex_error&) {
        return false;
    }
    return true;
}

// Read the command line parameters from argv and fill in the given structure
int fill_params(ParamStruct& user_param, int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") {
            print_help();
            return 1;
        } else if (arg == "-r") {
            user_param.request_file = argv[++i];
        } else if (arg == "-u") {
            user_param.users_file = argv[++i];
        } else if (arg == "-p") {
            user_param.passwords_file = argv[++i];
        } else if (arg == "-n") {
            if (validate_regex(argv[++i])) {
                user_param.regex_patterns.push_back(argv[i]);
            } else {
                std::cout << "Invalid regular expression: " << argv[i] << std::endl;
                return -1;
            }
        } else if (arg == "-N") {
            user_param.string_patterns.push_back(argv[i]);
        } else if (arg == "-i") {
            user_param.invert_pattern = true;
        } else if (arg == "-w") {
            user_param.request_delay = std::stoi(argv[++i]);
        } else if (arg == "-d") {
            user_param.domain = argv[++i];
        } else if (arg == "-t") {
            user_param.num_proc = std::stoi(argv[++i]);
        } else if (arg == "-o") {
            user_param.pot_file = argv[++i];
        } else if (arg == "-v") {
            user_param.verbose = true;
        } else if (arg == "-c") {
            user_param.ignore_http_status_codes = argv[++i];
        }
    }
    return 0;
}

// Check if an ip address or domain is reachable
bool is_valid_ip_address_or_domain(const std::string& domain) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return false;
    }

    // Set the URL to perform DNS resolution
    curl_easy_setopt(curl, CURLOPT_URL, domain.c_str());

    // Set the CURLOPT_NOBODY option to skip the body of the response
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);

    // Set the CURLOPT_CONNECT_ONLY option to make libcurl only do the connection phase
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);

    // Set a timeout for the DNS resolution process (in seconds)
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);  // Set timeout to 5 seconds

    // Perform the connection
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    // Check the result of the response
    if (res != CURLE_OK) {
        return false;
    }

    return true;
}


// +++ String manipulation +++

std::string get_content_length(const std::string& request) {

    // Find the double newline that seperates headers and body
    size_t pos = request.find("\n\n") + 2;
    if (pos == std::string::npos) {
        std::cout << "get_content_length: no double newline found" << std::endl;
        return "0";
    }

    // Extract body and calculate its length
    std::string body = request.substr(pos);
    int line_length = body.length();
    return std::to_string(line_length);
}

// Replace a value in a string
void replace(std::string& str, const std::string& oldStr, const std::string& newStr) {
    size_t pos = 0;
    while ((pos = str.find(oldStr, pos)) != std::string::npos) {
        str.replace(pos, oldStr.length(), newStr);
        pos += newStr.length();
    }
}

// URL encode a string
std::string url_encode(const std::string& decoded) {
    const auto encoded_value = curl_easy_escape(nullptr, decoded.c_str(), static_cast<int>(decoded.length()));
    std::string result(encoded_value);
    curl_free(encoded_value);
    return result;
}


// +++ Files +++

// Read usernames and passwords file to memory (return vector of pairs)
// 1st iteration: usernames, 2nd iteration: passwords
std::vector<std::pair<std::string, std::string>> process_passwords_and_usernames_file(std::ifstream& file1, std::ifstream& file2, int buffer_size) {
    std::vector<std::pair<std::string, std::string>> result;
    std::string line2;
    int combinations = 0;

    while (combinations < buffer_size && std::getline(file2, line2)) {
        std::string line1;
        if (line2 == "") {
            continue;
        }
        while (std::getline(file1, line1)) {
            if (line1 == "") {
                continue;
            }
            result.emplace_back(std::make_pair(line1, line2));
            combinations++;
        }
        // Reset the file2 stream back to the beginning
        file1.clear();
        file1.seekg(0, std::ios::beg);
    }
    return result;
}

// Append string to file
bool append_string_to_file(const std::string& filename, const std::string& content) {
    std::ofstream file;
    file.open(filename, std::ios::out | std::ios::app);  // Open the file in append mode
    if (!file.is_open()) {
        // File does not exist, create it
        file.open(filename, std::ios::out);
        if (!file.is_open()) {
            std::cerr << "Error could not create pot_file: " << filename << std::endl;
            return false;
        }
    }
    file << content << "\n";
    file.close();
    return true;
}


// +++ main and helper +++

// Function to pop an item from the vector, store it in two new variables, and delete the item
bool pop_vector(std::vector<std::pair<std::string, std::string>>& logins, std::string& username, std::string& password) {
    if (logins.size() == 0) {
        return false;
    }
    std::pair<std::string, std::string> pair = logins.back();  // Get the last item from the vector    
    logins.pop_back();  // Remove the last item from the vector
    username = pair.first;
    password = pair.second;
    return true;
}

// Get Unix Time
std::time_t get_unix_time() {
    auto now = std::chrono::system_clock::now();

    // Convert the time point to a duration since the epoch
    auto duration = now.time_since_epoch();

    // Convert the duration to seconds
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);

    // Extract the count of seconds from the duration
    std::time_t unix_time = seconds.count();

    return unix_time;
}

// Count lines of a file
int count_lines(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return -1;
    }

    int lineCount = 0;
    std::string line;
    while (std::getline(file, line)) {
        if (line == "") {
            continue;
        }
        lineCount++;
    }

    file.close();
    return lineCount;
}

// Convert seconds to DD:HH:MM:SS
std::string seconds_to_dhms(int seconds) {
    int days = seconds / (24 * 3600);
    seconds %= (24 * 3600);
    int hours = seconds / 3600;
    seconds %= 3600;
    int minutes = seconds / 60;
    int remaining_seconds = seconds % 60;

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(2) << days << "d "
        << std::setfill('0') << std::setw(2) << hours << "h:" 
        << std::setfill('0') << std::setw(2) << minutes << "m:" 
        << std::setfill('0') << std::setw(2) << remaining_seconds << "s";

    return oss.str();
}

// Process user parameter status code ranges
std::vector<std::pair<int, int>> process_status_code_ranges(const std::string& str) {
    std::vector<std::pair<int, int>> ranges;

    std::istringstream iss(str);
    std::string token;
    while (std::getline(iss, token, ',')) {
        std::istringstream token_stream(token);
        int start, end;
        char dash;
        token_stream >> start;
        if (token_stream >> dash >> end) {
            ranges.push_back({start, end});
        } else {
            ranges.push_back({start, start});  // Single number
        }
    }

    return ranges;
}

// Verify wether a number is within a range
bool is_in_ranges(int num, const std::vector<std::pair<int, int>>& ranges) {
    for (const auto& range : ranges) {
        if (num >= range.first && num <= range.second) {
            return true;
        }
    }
    return false;
}

// Extract the path from the request file
std::string extract_path(const std::string& requestLine) {
    std::istringstream stream(requestLine);
    std::string method, path, protocol;
    
    // Extract method, path, and protocol
    if (stream >> method >> path >> protocol) {
        return path;  // Return only the path
    }

    return "";  // Return an empty string if parsing fails
}
