/*
    Loginclear is a web login brute-forcing tool.
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

#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <cstring>
#include <array>
#include <signal.h>
#include <vector>
#include <fcntl.h>
#include <fstream>
#include <curl/curl.h>
#include <random>
#include <cstdlib>
#include <iomanip>
#include <arpa/inet.h>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <netdb.h>
#include <regex>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <string>
#include <sys/ioctl.h>

#include "loginclear.h"


int main(int argc, char* argv[]) {
    // Start timer
    std::time_t process_start_time = get_unix_time();;
    std::string process_start_string = std::ctime(&process_start_time);
    process_start_string.erase(process_start_string.length() - 1);

    // Parse and verify command line parameters
    ParamStruct user_param;
    int ret = fill_params(user_param, argc, argv);
    if (ret == -1) {
        return EXIT_FAILURE;
    } else if (ret == 1) {
        return EXIT_SUCCESS;
    }
    if ((user_param.users_file == "") || (user_param.passwords_file == "")) {
        std::cerr << "-u and -p is required" << std::endl;
        return EXIT_FAILURE;
    } else if (user_param.request_file == "") {
        std::cerr << "-r is required" << std::endl;
        return EXIT_FAILURE;
    } else if (user_param.string_patterns.empty() && user_param.regex_patterns.empty()) {
        std::cerr << "-n/-N is required" << std::endl;
        return EXIT_FAILURE;
    } else if (user_param.domain == "") {
        std::cerr << "-d is required" << std::endl;
        return EXIT_FAILURE;
    } else if (user_param.domain.substr(0, 7) != "http://" && user_param.domain.substr(0, 8) != "https://") {
        std::cerr << "Include http:// or https:// in the URL (-d)" << std::endl;
        return EXIT_FAILURE;
    } else if (!is_valid_ip_address_or_domain(user_param.domain)) {
        std::cerr << "Connection to ip-or-domain[:port] failed (-d)" << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<std::pair<int, int>> parsed_http_status_code_ranges = process_status_code_ranges(user_param.ignore_http_status_codes);
    
    // Print user parameters for testing
    if (user_param.verbose) {
        std::cout << "Parameters:" << std::endl;
        std::cout << "request_file: " << user_param.request_file << std::endl;
        std::cout << "users_file: " << user_param.users_file << std::endl;
        std::cout << "passwords_file: " << user_param.passwords_file << std::endl;
        std::cout << "URL: " << user_param.domain << std::endl;
        std::cout << "string patterns: ";
        for (size_t i = 0; i < user_param.string_patterns.size(); ++i) {
            std::cout << user_param.string_patterns[i];
            if (i != user_param.string_patterns.size() - 1) {
                std::cout << ", ";
            }
        }
        std::cout << std::endl;
        std::cout << "regex patterns: ";
        for (size_t i = 0; i < user_param.regex_patterns.size(); ++i) {
            std::cout << user_param.regex_patterns[i];
            if (i != user_param.regex_patterns.size() - 1) {
                std::cout << ", ";
            }
        }
        std::cout << std::endl;
        std::cout << "invert: " << user_param.invert_pattern << std::endl;
        std::cout << "delay: " << user_param.request_delay << std::endl;
        std::cout << "num_proc: " << user_param.num_proc << std::endl;
        std::cout << "pot_file: " << user_param.pot_file << std::endl;
        std::cout << "verbose: " << user_param.verbose << std::endl;
        std::cout << "ignore HTTP status codes: " << user_param.ignore_http_status_codes << std::endl;
        std::cout << std::endl;
    }

    // Fetch request template from disk
    std::ifstream request_file(user_param.request_file);
    if (!request_file.is_open()) {
        std::cerr << "Error: Could not open the file " << user_param.request_file << std::endl;
        return EXIT_FAILURE;
    }
    std::string http_request((std::istreambuf_iterator<char>(request_file)), std::istreambuf_iterator<char>());
    request_file.close();

    // Normalize newlines for parsing
    // Newlines in the HTTP header must obey the HTTP standard which is handled by cURL while newlines in the body are not constrained
    replace(http_request, "\r\n", "\n");

    // Extract the URL path
    std::string path = extract_path(http_request);

    // Print info about request template
    if (user_param.verbose) {
        std::cout << user_param.request_file << " info:" << std::endl;
        std::cout << "Extracted HTTP path " << path << std::endl;
        if (http_request.find("USERNAME") != std::string::npos || http_request.find("e(USERNAME)") != std::string::npos) {
            std::cout << "Found user payload field USERNAME or e(USERNAME)" << std::endl;
        }
        if (http_request.find("PASSWORD") != std::string::npos || http_request.find("e(PASSWORD)") != std::string::npos) {
            std::cout << "Found password payload field PASSWORD or e(PASSWORD)" << std::endl;
        }
        if (http_request.find("\n\n") == std::string::npos) {
            std::cout << "No HTTP body detected" << std::endl;
        }
        std::cout << std::endl;
    }

    // Create a shared memory region
    size_t shared_size = sizeof(IpcStruct);
    IpcStruct *shared_memory = (IpcStruct *)mmap(NULL, shared_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shared_memory == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Initialize semaphore
    sem_t *sem = sem_open(SEM_NAME, O_CREAT, 0666, 1);
    if (sem == SEM_FAILED) {
        perror("sem_open failed");
        return EXIT_FAILURE;
    }

    // Fork
    pid_t main_pid = getpid();
    std::vector<pid_t> child_pids(user_param.num_proc, 0);
    for (int child_num = 0; child_num < user_param.num_proc; ++child_num) {
        pid_t pid = fork();
        if (pid == -1) {
            std::cerr << "Error forking child process " << child_num << std::endl;
            return EXIT_FAILURE;
        } else if (pid == 0) {
            // Child process
            
            // Create cURL handle
            CURL *curl;
            curl_global_init(CURL_GLOBAL_ALL);
            curl = curl_easy_init();
            if (!curl) {
                std::cout << "Curl could not be initialized" << std::endl;
                return EXIT_FAILURE;
            }

            // Set cURL options (will be used for all future requests using this handle)
            curl_easy_setopt(curl, CURLOPT_URL, user_param.domain.c_str());  // Set the target domain and custom callback function
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 4L);              // Set the connection timeout (in seconds)

            // Set up callback for the HTTP response body
            CallbackParam callback_param;
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writer_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &callback_param);

            std::string next_login;
            std::string username;
            std::string password;
            std::string content_length;
            std::string next_http_request;
            int request_delay = user_param.request_delay;
            size_t pos;
            bool retry = false;
            std::vector<std::string> buffer_in_child;
            while (true) {

                sleep_chrono(request_delay, 0);
                
                // Try to fetch new logins
                if (buffer_in_child.empty()) {
                
                    sem_wait(sem);

                    // Exit or wait for new logins if the buffer is empty
                    if (is_buffer_empty(shared_memory->buffer_in_ipc)) {
                        if (shared_memory->no_more_logins) {

                            sem_post(sem);

                            break;
                        }
                        
                        sem_post(sem);

                        sleep_chrono(100, 0);
                        continue;
                    }

                    // Refill buffer
                    for (int i = 0; i < BUFFER_IN_IPC_SIZE && buffer_in_child.size() < BUFFER_IN_CHILD_SIZE; i++) {
                        if (shared_memory->buffer_in_ipc[i][0] != '\0') {
                            buffer_in_child.push_back(shared_memory->buffer_in_ipc[i].data());
                            shared_memory->buffer_in_ipc[i][0] = '\0';
                        }
                    }

                    // Status update
                    std::memcpy(shared_memory->status.current_login.data(), next_login.c_str(), next_login.size()+1);

                    sem_post(sem);

                    sleep_chrono(100, 0);
                    continue;
                }
                
                // Pop a login from the shared memory buffer login array
                if (!retry) {
                    next_login = buffer_in_child.back();
                    buffer_in_child.pop_back();
                }

                // Extract username and password
                pos = next_login.find(':');
                username = next_login.substr(0, pos);
                password = next_login.substr(pos + 1);

                // Save login in the callback parameters
                callback_param.total_received = 0;
                callback_param.response_data = "";
                callback_param.match = false;
                
                // Substitute login data in the request
                next_http_request = http_request;
                replace(next_http_request, "USERNAME", username);
                replace(next_http_request, "PASSWORD^", password);

                // URL encode
                std::string encoded_username = url_encode(username);
                std::string encoded_password = url_encode(password);
                replace(next_http_request, "e(USERNAME)", encoded_username);
                replace(next_http_request, "e(PASSWORD)", encoded_password);

                // Enable HTTP headers in the response
                curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

                // Seperate headers and body
                std::string body = "";
                std::string headers;
                size_t header_end = next_http_request.find("\n\n");
                if (header_end != std::string::npos) {
                    headers = next_http_request.substr(0, header_end);
                    body = next_http_request.substr(header_end + 2);
                } else {
                    headers = next_http_request;
                }

                // Set headers and body on cURL handle
                struct curl_slist* curl_headers = nullptr;
                pos = 1;
                size_t line_end;
                bool content_length_found = false;
                content_length = get_content_length(next_http_request);
                while ((line_end = headers.find("\n", pos)) != std::string::npos) {
                    std::string header_line = headers.substr(pos, line_end - pos);

                    // Adjust Content-Length
                    if (header_line.find("Content-Length: ") == 0) {
                        header_line = "Content-Length: " + content_length;
                        content_length_found = true;
                    }

                    curl_headers = curl_slist_append(curl_headers, header_line.c_str());
                    pos = line_end + 1;
                }
                if (!content_length_found && content_length != "0") {
                    std::string content_length_header = "Content-Length: " + content_length;
                    curl_headers = curl_slist_append(curl_headers, content_length_header.c_str());
                }
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

                // Perform error-safe request
                while (retry == false && shared_memory->fail_counter != 0) {
                    // This loop ensures only one child process continues until network is restored
                    sleep_chrono(1000, 5000);
                }
                if (curl_easy_perform(curl) != CURLE_OK) {

                    sem_wait(sem);

                    shared_memory->fail_counter++;
                    if (shared_memory->fail_counter < 6) {
                        shared_memory->status.total_retries++;
                    }

                    sem_post(sem);

                    sleep_chrono(std::pow(2, shared_memory->fail_counter) * 1000, 0);
                    retry = true;
                    continue;
                } else if (retry == true) {
                    retry = false;

                    sem_wait(sem);
                    shared_memory->fail_counter = 0;
                    sem_post(sem);

                }

                curl_slist_free_all(curl_headers);  // Crucial to prevent memory leakage
                
                // Find pattern in response
                bool match = false;
                for (const auto& pattern : user_param.string_patterns) {
                    if (callback_param.response_data.find(pattern) != std::string::npos) {
                        match = true;
                        break;
                    }
                }
                if (!match) {
                    for (const auto& pattern : user_param.regex_patterns) {
                        std::regex regex_pattern(pattern);
                        if (std::regex_search(callback_param.response_data, regex_pattern)) {
                            match = true;
                            break;
                        }
                    }
                }

                sem_wait(sem);

                shared_memory->status.total_requests++;
                
                // Write successful matches to shared memory
                if (match ^ user_param.invert_pattern) {
                    for (int i=0; i < BUFFER_IN_IPC_SIZE; i++) {
                        if (shared_memory->buffer_out_ipc[i][0] == '\0') {
                            /*
                            when the logins are written to the IPC buffer the size limit of MAX_LOGIN_LEN is enforced
                            therefore, a check is not necessary
                            */
                            std::memcpy(shared_memory->buffer_out_ipc[i].data(), next_login.c_str(), next_login.size()+1);
                            break;
                        }
                    }
                }

                // Append data to status

                // Amount of data received
                shared_memory->status.total_gb_received += static_cast<double>(callback_param.total_received) / (1024 * 1024 * 1024);

                // Amount of data sent
                shared_memory->status.total_gb_sent += static_cast<double>(next_http_request.length()) / (1024 * 1024 * 1024);

                // Response time
                double response_time;
                curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &response_time);
                shared_memory->status.total_response_time += response_time * 1000000;

                sem_post(sem);

                // Check status code
                int response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                if (is_in_ranges(response_code, parsed_http_status_code_ranges)) {
                    continue;
                }
            }

            // Clean up
            curl_global_cleanup();

            return EXIT_SUCCESS;
        } else {
            // Collect child PIDs for parent process
            child_pids[child_num] = pid;
        }
    }

    // Parent process
    if (getpid() == main_pid) {
        
        std::vector<std::string> buffer_out_parent;  // Vector for valid logins

        // Open and process files
        // The files are closed when the program finishes because they are processed gradually
        std::vector<std::pair<std::string, std::string>> buffer_in_parent;
        std::ifstream file1;
        std::ifstream file2;
        int total_combinations;
        total_combinations = count_lines(user_param.users_file);
        if (total_combinations == -1) {
            std::cerr << "Error: Could not open the file " << user_param.users_file << std::endl;
            return EXIT_FAILURE;
        }
        int lines2 = count_lines(user_param.passwords_file);
        if (lines2 == -1) {
            std::cerr << "Error: Could not open the file " << user_param.passwords_file << std::endl;
            return EXIT_FAILURE;
        }
        total_combinations *= lines2;
        file1.open(user_param.users_file);
        if (!file1.is_open()) {
            std::cerr << "Error: Could not open the file " << user_param.users_file << std::endl;
            return EXIT_FAILURE;
        }
        file2.open(user_param.passwords_file);
        if (!file2.is_open()) {
            std::cerr << "Error: Could not open the file " << user_param.passwords_file << std::endl;
            return EXIT_FAILURE;
        }
        buffer_in_parent = process_passwords_and_usernames_file(file1, file2, BUFFER_IN_IPC_SIZE * user_param.num_proc);

        int status_lines = 10;
        std::string initial_padding(status_lines, '\n');
        std::cout << initial_padding;

        // Brute Forcing Loop
        std::string username;
        std::string password;
        std::string next_login;
        std::string valid_login;
        int waitpid_status;
        bool childrenFinished = false;
        while (!childrenFinished) {
            
            sleep_chrono(150, 0);

            sem_wait(sem);

            // Refill parent in buffer and exit routine
            if (buffer_in_parent.empty()) {
                if (!file1.eof() && !file2.eof()) {
                    buffer_in_parent = process_passwords_and_usernames_file(file1, file2, BUFFER_IN_IPC_SIZE * user_param.num_proc);
                }

                // If the buffer is still empty the files are finished and the program can exit
                if (buffer_in_parent.empty() && shared_memory->buffer_out_ipc[0][0] == '\0') {
                    shared_memory->no_more_logins = true;  // Set flag to exit child processes
                    childrenFinished = true;  // While loop condition
                    // Don't exit before children are finished to fetch all valid logins
                    for (int i = 0; i < user_param.num_proc; ++i) {
                        if (waitpid(child_pids[i], &waitpid_status, WNOHANG) == 0) {
                            childrenFinished = false;
                            // At least one child is still running

                            sem_post(sem);
                            sleep_chrono(500, 0);
                            sem_wait(sem);  // Acquire semaphore again to fetch possible valid logins

                            break;
                        }
                    }
                }
            }
            
            // Refill IPC in buffer
            if (is_buffer_empty(shared_memory->buffer_in_ipc)) {
                int count=0;
                for (int i=0; i < BUFFER_IN_IPC_SIZE; i++) {
                    if (shared_memory->buffer_in_ipc[i][0] == '\0') {
                        if (!pop_vector(buffer_in_parent, username, password)) {
                            break;
                        }
                        next_login = username + ":" + password;
                        if (next_login.length() > MAX_LOGIN_LEN) {
                            continue;
                        }
                        std::memcpy(shared_memory->buffer_in_ipc[i].data(), next_login.c_str(), next_login.size()+1);
                        count++;
                    } else {
                        break;  // Skip the rest of the array which is guaranteed to be filled already
                    }
                }
            }

            // Fetch valid logins
            if (shared_memory->buffer_out_ipc[0][0] != '\0') {  // Redundant but helps to keep performance up
                for (int i = 0; i < BUFFER_OUT_IPC_SIZE; i++) {
                    if (shared_memory->buffer_out_ipc[i][0] != '\0') {
                        valid_login = shared_memory->buffer_out_ipc[i].data();
                        if (std::find(buffer_out_parent.begin(), buffer_out_parent.end(), valid_login) == buffer_out_parent.end()) {
                            buffer_out_parent.emplace_back(valid_login);
                            if (user_param.pot_file != "") {
                                append_string_to_file(user_param.pot_file, valid_login);
                            }
                        }
                        shared_memory->buffer_out_ipc[i][0] = 0;
                    }
                }
            }

            // Print status
            std::string status_output = "";
            std::time_t duration = get_unix_time() - process_start_time + 1;
            status_output += "Clearing login: ";
            status_output += user_param.domain;
            status_output += path;
            status_output += "\nProgress: ";
            float progress = (static_cast<float>(shared_memory->status.total_requests) / total_combinations) * 100.0;
            std::stringstream progress_string;
            progress_string << std::fixed << std::setprecision(3) << progress;
            status_output += progress_string.str();
            status_output += "%\n\n";

            status_output += "Wordlist length: ";
            status_output += std::to_string(total_combinations);
            status_output += "\n";

            status_output += "Pakets sent: ";
            status_output += std::to_string(shared_memory->status.total_requests);
            status_output += "\n";

            status_output += "Send rate: ";
            status_output += std::to_string(static_cast<int>(shared_memory->status.total_requests / duration));
            status_output += "/s\n";

            status_output += "Average response time: ";
            status_output += std::to_string(static_cast<int>(shared_memory->status.total_response_time / shared_memory->status.total_requests));
            status_output += " microseconds\n";

            status_output += "Start time: ";
            status_output += process_start_string;
            status_output += "\n";

            status_output += "Elapsed time: ";
            status_output += seconds_to_dhms(duration);
            status_output += "\n";

            status_output += "Estimated time remaining: ";
            // Calculate the remaining workload
            int remaining_workload = total_combinations - shared_memory->status.total_requests;

            // Calculate the completion rate (items per second)
            double completion_rate = static_cast<double>(shared_memory->status.total_requests) / duration;

            // Calculate remaining time in seconds
            int remaining_time_seconds = static_cast<int>(remaining_workload / completion_rate);

            // Calculate ETA in seconds from the current time
            time_t current_time;
            time(&current_time);
            current_time += remaining_time_seconds;

            // Convert to a readable date/time format
            struct tm* eta_time_info = localtime(&current_time);
            char eta_str[100];
            strftime(eta_str, sizeof(eta_str), "%c", eta_time_info);

            status_output += eta_str;
            status_output += " in: ";
            status_output += seconds_to_dhms(remaining_time_seconds);
            status_output += "\n";

            if (shared_memory->status.total_retries != 0) {
                status_output += "Total retries: ";
                status_output += std::to_string(shared_memory->status.total_retries);
                status_output += "\n";
            }

            status_output += "Total data transferred: ";
            status_output += std::to_string(shared_memory->status.total_gb_sent);
            status_output += " GB sent / ";
            status_output += std::to_string(shared_memory->status.total_gb_received);
            status_output += " GB received\n\n";

            if (buffer_out_parent.size() != 0) {
                status_output += "Logins found: ";
                for (size_t i = 0; i < buffer_out_parent.size(); i++) {
                    if (i > 0) {
                        status_output += ", ";
                    }
                    status_output += buffer_out_parent[i].data();
                }
                status_output += "\n";
            }

            status_output += "Current candidate: ";
            status_output += shared_memory->status.current_login.data();

            if (shared_memory->fail_counter != 0) {
                status_output += "\nNo connection, retrying in: ";
                status_output += std::to_string(static_cast<int>(std::pow(2, shared_memory->fail_counter)));
                status_output += " seconds";
            }

            sem_post(sem);

            // Clear last output and print
            for (int i = 0; i < status_lines; i++) {
                std::cout << "\r\033[K";  // Clear the line
                std::cout << "\033[1A";   // Move the cursor up one line
            }
            std::cout << "\r\033[K";
            std::cout << status_output << std::flush;

            status_lines = std::count(status_output.begin(), status_output.end(), '\n');
        }

        // Program finished

        // Close the files
        file1.close();
        file2.close();

        // Unmap the shared memory region
        if (munmap(shared_memory, shared_size) == -1) {
            perror("munmap");
            return EXIT_FAILURE;
        }

        // Close semaphore
        sem_unlink(SEM_NAME);

        return EXIT_SUCCESS;
    }
}
