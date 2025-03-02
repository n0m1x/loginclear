# Loginclear

## Introduction
Web login brute forcing is the method of automated guessing of login credentials for web application logins. Unlike hash cracking, where guesses are computed locally, this approach requires sending each attempt over the network, introducing significant delays. Additionally, defenses like rate limiting and CAPTCHAs can restrict its effectiveness. Therefore, improving performance to the limit is 

Loginclear was created in an attempt to surpass tools like Hydra and Burp Suite in web login brute forcing. Many improvements and refinements paved the way from the initial proof of concept to the tool presented here. At its core, Loginclear leverages multiprocessing and inter-process communication to scale performance and efficiently process data. In its final development stage, improving usability and reducing complexity of use were key priorities. The tool is meant to be used in combination with Burp Suite or the browser developer console for setup and is built to run for extended periods of time.

## Getting Started

### Installation
The tool can be installed on a debian system the following way:
```
sudo apt update
sudo apt install libcurl4-openssl-dev git
git clone https://github.com/n0m1x/loginclear
cd loginclear
make
sudo make install
```

### Preparation
Three components are required to start:
1. Username and password wordlists (`-u users.txt -p passwords.txt`).
2. A raw HTTP request template including headers, body and the placeholders `USERNAME` and `PASSWORD` (see the example below). A sample can be obtained from the browser developer console or Burp Suite. Add it as a text file to the parameters (`-r request.txt`).
3. A regular expression or string to filter successful logins. The entire response including HTTP headers, body, and status line is searched for the specified pattern. Responses can for example be matched by their status code (e.g. `-n "HTTP/1.1 302 Found"`) or a string in the HTML body (e.g. `-n "Login successful"`). Matching can be inverted with `-i` (e.g. `-n "Login failed" -i`).

Below is an example HTTP request template. Placeholders enclosed in e(...) will be automatically URL-encoded. The Content-Length header will automatically be adjusted per request.
```
POST /login HTTP/1.1
Host: <domain name or ip address>
Content-Length: 10

username=e(USERNAME)&password=e(PASSWORD)
```

### Running
Once the requirements are met the tool can be launched
```
loginclear -u users.txt -p passwords.txt -r request.txt -n "Login successful" -d http://example.com
```
In this case, if the response contains the string ‘Login successful' the corresponding username-password pair is printed to the terminal.

### Optional Parameters
The following optional parameters are available.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-t <int>` | Specify the number of processes to use to tune performance. | `4` |
| `-w <int>` | Specify a delay between requests in milliseconds (e.g. `-w 2000` for two seconds). | `0` |
| `-c <range>` | HTTP status codes that should be ignored. See the help menu for formatting. | `400-599` |
| `-o <str>` | A file where successful candidates will be stored (e.g. `-o potfile.txt`). | n/a |

## License
Distributed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html). See LICENSE for more information.
