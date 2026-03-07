# Contributing to Network Security Scanner (NSS)

## Adding New Checks
1. Identify module: mgmt_plane, ctrl_plane, data_plane, services, switch_security, wireless, ngfw_core, ngfw_platform, logging, crypto
2. Add check method to the appropriate auditor class
3. Create sample config demonstrating the issue in sample_configs/
4. Test and submit PR

## Code Style
- Python 3.8+, zero dependencies
- Type hints, docstrings on all classes
- Test with sample configs before submitting
