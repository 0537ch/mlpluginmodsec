# ModSecurity ML Plugin Test

This is a simple test setup for ModSecurity Lua plugin integration.

## Structure
- `machine-learning-client.lua`: The Lua plugin file
- `machine-learning.conf`: ModSecurity configuration file
- `logs/`: Directory for log files (will be created automatically)

## Setup
1. Copy these files to your ModSecurity configuration directory
2. Create a logs directory
3. Include the `machine-learning.conf` in your ModSecurity configuration
4. Restart Apache

## Testing
Access any URL on your web server and check the debug log at `logs/modsec_debug.log`
