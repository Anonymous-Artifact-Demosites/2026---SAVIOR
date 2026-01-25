#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone 2Captcha caller
Works in both Python and packaged EXE environments
Can be called by Claude AI using bash/subprocess
"""

import sys
import os
import json


def main():
    """Call 2captcha with provided arguments"""
    if len(sys.argv) < 2:
        error_msg = {
            'success': False,
            'error': 'No command provided. Usage: python call_2captcha.py <command> [args...]'
        }
        print(json.dumps(error_msg), file=sys.stderr)
        sys.exit(1)
    
    # Get arguments
    args = sys.argv[1:]
    
    # Check if running from packaged exe
    is_packaged = getattr(sys, 'frozen', False)
    
    if is_packaged:
        # Running from exe - import and call directly
        try:
            # Backup and replace sys.argv
            original_argv = sys.argv.copy()
            sys.argv = ['2captcha'] + args
            
            # Import 2captcha module
            import importlib
            captcha_module = importlib.import_module('2captcha')
            
            # Call main function
            captcha_module.main()
            
            # Restore sys.argv
            sys.argv = original_argv
            
        except SystemExit as e:
            sys.argv = original_argv
            sys.exit(e.code if e.code is not None else 0)
        except Exception as e:
            sys.argv = original_argv
            error_msg = {
                'success': False,
                'error': f'Exception in 2captcha: {str(e)}'
            }
            print(json.dumps(error_msg), file=sys.stderr)
            sys.exit(1)
    else:
        # Running from Python - use subprocess to call 2captcha.py
        import subprocess
        
        # Find 2captcha.py in the same directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        captcha_script = os.path.join(script_dir, '2captcha.py')
        
        if not os.path.exists(captcha_script):
            error_msg = {
                'success': False,
                'error': f'2captcha.py not found at: {captcha_script}'
            }
            print(json.dumps(error_msg), file=sys.stderr)
            sys.exit(1)
        
        # Call 2captcha.py
        cmd = [sys.executable, captcha_script] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        # Output results
        if result.stdout:
            print(result.stdout, end='')
        if result.stderr:
            print(result.stderr, end='', file=sys.stderr)
        
        sys.exit(result.returncode)


if __name__ == '__main__':
    main()

