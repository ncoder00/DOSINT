# DOSINT - Domain OSINT Tool

DOSINT is a command-line tool for performing domain intelligence gathering. It provides functionalities like WHOIS lookup, DNS lookup, SSL certificate details, port scanning, HTTP header analysis, and geolocation information.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

What you need to install the software:

- Python 3.x
- Git (optional, for cloning the repository)

### Installing

A step-by-step series of examples that tell you how to get a development environment running:

#### 1. Clone the repository (optional)

If you have git installed, you can clone the repository by running:

```bash
git clone https://github.com/ncoder00/DOSINT.git
cd dosint
```

#### 2. Set up a virtual environment

First, install `virtualenv` if you haven't installed it yet:

```bash
pip install virtualenv
```

Then, create and activate a virtual environment:

- On Windows:

```bash
python -m venv env
env\Scripts\activate
```

- On macOS and Linux:

```bash
python3 -m venv env
source env/bin/activate
```

#### 3. Install the required packages

Install all dependencies from the `requirements.txt` file:

```bash
pip install -r requirements.txt
```

### Running the Application

To run the application, use the following command:

```bash
python main.py
```

Follow the on-screen prompts to use different features of the tool.

## Built With

* [Python](https://www.python.org/) - The programming language used.
* [Rich](https://rich.readthedocs.io/en/latest/) - Library used for rich text and beautiful formatting in the terminal.

## Authors

* **Nivin** - [ncoder00](https://github.com/ncoder00)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

