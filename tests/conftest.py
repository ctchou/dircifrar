
# Command-line option to specify whether to test Rust module Oxido
def pytest_addoption(parser):
    parser.addoption('--test_oxido', action='store_true', default=False)
