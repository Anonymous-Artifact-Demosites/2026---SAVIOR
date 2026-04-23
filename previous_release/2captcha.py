import sys
import json
import os
from twocaptcha import TwoCaptcha

def get_api_key():
    """
    Get API key in priority order:
    1. Environment variable TWOCAPTCHA_API_KEY
    2. Command line argument (if --api-key is provided)
    3. Return None if no API key is provided (user must provide one)
    """
    # Priority 1: Environment variable
    api_key = os.environ.get('TWOCAPTCHA_API_KEY')
    if api_key and api_key.strip():
        return api_key.strip()
    
    # Priority 2: Command line argument (check for --api-key flag)
    if '--api-key' in sys.argv:
        idx = sys.argv.index('--api-key')
        if idx + 1 < len(sys.argv):
            key = sys.argv[idx + 1].strip()
            if key:
                return key
    
    # Priority 3: No fallback - user must provide API key
    return None

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    # Remove --api-key from argv if present (to avoid interfering with command parsing)
    if '--api-key' in sys.argv:
        idx = sys.argv.index('--api-key')
        sys.argv.pop(idx)  # Remove --api-key
        if idx < len(sys.argv):
            sys.argv.pop(idx)  # Remove API key value
    
    api_key = get_api_key()
    if not api_key:
        print(json.dumps({'success': False, 'error': 'No API key provided. Please set TWOCAPTCHA_API_KEY environment variable or use --api-key flag.'}), file=sys.stderr)
        sys.exit(1)
    
    solver = TwoCaptcha(api_key)
    command = sys.argv[1].lower()
    
    try:
        if command == 'balance':
            balance = solver.balance()
            print(json.dumps({'success': True, 'balance': balance}))
        
        # 1. Normal Captcha
        elif command == 'normal':
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = solver.normal(sys.argv[2])
            print(json.dumps({'success': True, 'text': result['code']}))
        
        # 2. Text Captcha
        elif command == 'text':
            if len(sys.argv) < 3:
                raise ValueError("Missing question")
            result = solver.text(sys.argv[2])
            print(json.dumps({'success': True, 'text': result['code']}))
        
        # 3. reCAPTCHA v2
        elif command == 'recaptcha_v2':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.recaptcha(sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 4. reCAPTCHA v3
        elif command == 'recaptcha_v3':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            action = sys.argv[4] if len(sys.argv) > 4 else 'verify'
            min_score = float(sys.argv[5]) if len(sys.argv) > 5 else 0.3
            result = solver.recaptcha(
                sitekey=sys.argv[2],
                url=sys.argv[3],
                version='v3',
                action=action,
                min_score=min_score
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 5. reCAPTCHA Enterprise
        elif command == 'recaptcha_enterprise':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.recaptcha(
                sitekey=sys.argv[2],
                url=sys.argv[3],
                enterprise=1
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 6. hCaptcha
        elif command == 'hcaptcha':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.hcaptcha(sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 7. FunCaptcha
        elif command == 'funcaptcha':
            if len(sys.argv) < 4:
                raise ValueError("Missing public_key and page_url")
            result = solver.funcaptcha(sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 8. GeeTest v3
        elif command == 'geetest':
            if len(sys.argv) < 5:
                raise ValueError("Missing gt, challenge, and page_url")
            result = solver.geetest(
                gt=sys.argv[2],
                challenge=sys.argv[3],
                url=sys.argv[4]
            )
            print(json.dumps({'success': True, 'response': result}))
        
        # 9. GeeTest v4
        elif command == 'geetest_v4':
            if len(sys.argv) < 4:
                raise ValueError("Missing captcha_id and page_url")
            result = solver.geetest_v4(
                captcha_id=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'response': result}))
        
        # 10. Cloudflare Turnstile (supports both Standalone and Challenge Page modes)
        elif command == 'turnstile':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            
            # Basic parameters (Standalone mode)
            params = {
                'sitekey': sys.argv[2],
                'url': sys.argv[3]
            }
            
            # Optional parameters for Challenge Page
            # Usage: turnstile <sitekey> <url> [action] [data] [pagedata]
            if len(sys.argv) > 4 and sys.argv[4]:
                params['action'] = sys.argv[4]
            if len(sys.argv) > 5 and sys.argv[5]:
                params['data'] = sys.argv[5]
            if len(sys.argv) > 6 and sys.argv[6]:
                params['pagedata'] = sys.argv[6]
            
            result = solver.turnstile(**params)
            
            # Return token and userAgent (Challenge Page will return userAgent)
            response = {'success': True, 'token': result['code']}
            if 'userAgent' in result:
                response['userAgent'] = result['userAgent']
            
            print(json.dumps(response))
        
        # 10b. Cloudflare Turnstile (JSON input mode - recommended for Challenge Page)
        elif command == 'turnstile_json':
            if len(sys.argv) < 3:
                raise ValueError("Missing JSON parameters")
            
            # Parse JSON parameters
            # Usage: turnstile_json '{"sitekey":"...","url":"...","action":"...","data":"...","pagedata":"..."}'
            params = json.loads(sys.argv[2])
            
            # Validate required fields
            if 'sitekey' not in params or 'url' not in params:
                raise ValueError("Missing required fields: sitekey and url")
            
            result = solver.turnstile(
                sitekey=params['sitekey'],
                url=params['url'],
                action=params.get('action'),
                data=params.get('data'),
                pagedata=params.get('pagedata')
            )
            
            # Return token and userAgent (Challenge Page will return userAgent)
            response = {'success': True, 'token': result['code']}
            if 'userAgent' in result:
                response['userAgent'] = result['userAgent']
            
            print(json.dumps(response))
        
        # 11. KeyCaptcha
        elif command == 'keycaptcha':
            if len(sys.argv) < 7:
                raise ValueError("Missing parameters")
            result = solver.keycaptcha(
                s_s_c_user_id=sys.argv[2],
                s_s_c_session_id=sys.argv[3],
                s_s_c_web_server_sign=sys.argv[4],
                s_s_c_web_server_sign2=sys.argv[5],
                url=sys.argv[6]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 12. Capy Puzzle
        elif command == 'capy':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.capy(sitekey=sys.argv[2], url=sys.argv[3])
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 13. Grid (Click Captcha)
        elif command == 'grid':
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = solver.grid(sys.argv[2])
            print(json.dumps({'success': True, 'coordinates': result['code']}))
        
        # 14. Rotate Captcha
        elif command == 'rotate':
            if len(sys.argv) < 3:
                raise ValueError("Missing image_path")
            result = solver.rotate(sys.argv[2])
            print(json.dumps({'success': True, 'angle': result['code']}))
        
        # 15. Amazon WAF
        elif command == 'amazon_waf':
            if len(sys.argv) < 6:
                raise ValueError("Missing parameters")
            result = solver.amazon_waf(
                sitekey=sys.argv[2],
                iv=sys.argv[3],
                context=sys.argv[4],
                url=sys.argv[5]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 16. Lemin Captcha
        elif command == 'lemin':
            if len(sys.argv) < 5:
                raise ValueError("Missing captcha_id, div_id, and page_url")
            result = solver.lemin(
                captcha_id=sys.argv[2],
                div_id=sys.argv[3],
                url=sys.argv[4]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 17. Atb Captcha
        elif command == 'atb':
            if len(sys.argv) < 5:
                raise ValueError("Missing app_id, api_server, and page_url")
            result = solver.atb_captcha(
                app_id=sys.argv[2],
                api_server=sys.argv[3],
                url=sys.argv[4]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 18. DataDome
        elif command == 'datadome':
            if len(sys.argv) < 4:
                raise ValueError("Missing captcha_url and page_url")
            result = solver.datadome(
                captcha_url=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 19. CyberSiARA
        elif command == 'cybersiara':
            if len(sys.argv) < 4:
                raise ValueError("Missing master_url_id and page_url")
            result = solver.cybersiara(
                master_url_id=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 20. MTCaptcha
        elif command == 'mtcaptcha':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.mtcaptcha(
                sitekey=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 21. Friendly Captcha
        elif command == 'friendly':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.friendly_captcha(
                sitekey=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 22. Cutcaptcha
        elif command == 'cutcaptcha':
            if len(sys.argv) < 5:
                raise ValueError("Missing misery_key, api_key, and page_url")
            result = solver.cutcaptcha(
                misery_key=sys.argv[2],
                apikey=sys.argv[3],
                url=sys.argv[4]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        # 23. Tencent Captcha
        elif command == 'tencent':
            if len(sys.argv) < 4:
                raise ValueError("Missing app_id and page_url")
            result = solver.tencent(
                app_id=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'response': result}))
        
        # 24. Audio Captcha
        elif command == 'audio':
            if len(sys.argv) < 3:
                raise ValueError("Missing audio_path")
            result = solver.audio(sys.argv[2])
            print(json.dumps({'success': True, 'text': result['code']}))
        
        # 25. Yandex SmartCaptcha
        elif command == 'yandex':
            if len(sys.argv) < 4:
                raise ValueError("Missing site_key and page_url")
            result = solver.yandex(
                sitekey=sys.argv[2],
                url=sys.argv[3]
            )
            print(json.dumps({'success': True, 'token': result['code']}))
        
        else:
            raise ValueError(f"Unknown command: {command}")
    
    except Exception as e:
        print(json.dumps({'success': False, 'error': str(e)}), file=sys.stderr)
        sys.exit(1)


def print_usage():
    """Print usage instructions"""
    usage = """
Complete 2Captcha Solver - All Captcha Types
Uses the official twocaptcha-python library

Usage: python 2captcha.py <command> [arguments...]

Top 12 Most Common:
  balance                                            - Check balance
  normal <image_path>                                - Normal captcha
  text <question>                                    - Text captcha
  recaptcha_v2 <site_key> <page_url>                - reCAPTCHA v2
  recaptcha_v3 <site_key> <page_url>                - reCAPTCHA v3
  recaptcha_enterprise <site_key> <page_url>        - reCAPTCHA Enterprise
  hcaptcha <site_key> <page_url>                    - hCaptcha
  funcaptcha <public_key> <page_url>                - FunCaptcha
  geetest <gt> <challenge> <page_url>               - GeeTest v3
  geetest_v4 <captcha_id> <page_url>                - GeeTest v4
  turnstile <site_key> <page_url>                   - Cloudflare Turnstile (Standalone)
  turnstile <site_key> <page_url> [action] [data] [pagedata]
                                                     - Cloudflare Turnstile (Challenge Page)
  turnstile_json '<json>'                           - Cloudflare Turnstile (JSON mode)
  keycaptcha <params...> <page_url>                 - KeyCaptcha
  capy <site_key> <page_url>                        - Capy Puzzle

Additional Types:
  grid <image_path>                                  - Grid/Click captcha
  rotate <image_path>                                - Rotate captcha
  amazon_waf <site_key> <iv> <context> <page_url>   - Amazon WAF
  lemin <captcha_id> <div_id> <page_url>            - Lemin
  atb <app_id> <api_server> <page_url>              - Atb Captcha
  datadome <captcha_url> <page_url>                 - DataDome
  cybersiara <master_url_id> <page_url>             - CyberSiARA
  mtcaptcha <site_key> <page_url>                   - MTCaptcha
  friendly <site_key> <page_url>                    - Friendly Captcha
  cutcaptcha <misery_key> <api_key> <page_url>      - Cutcaptcha
  tencent <app_id> <page_url>                       - Tencent Captcha
  audio <audio_path>                                - Audio captcha
  yandex <site_key> <page_url>                      - Yandex SmartCaptcha

Turnstile Examples:
  # Standalone (simple)
  python captcha_solver_complete.py turnstile 3x00000000000000000000FF https://example.com

  # Challenge Page (with parameters)
  python captcha_solver_complete.py turnstile 3x00000000000000000000FF https://example.com managed 80001aa1affffc21 3gAFo2l...UVTO=

  # JSON mode (recommended for Challenge Page)
  python captcha_solver_complete.py turnstile_json '{"sitekey":"3x00000000000000000000FF","url":"https://example.com","action":"managed","data":"80001aa1affffc21","pagedata":"3gAFo2l...UVTO="}'

"""
    print(usage)


if __name__ == '__main__':
    main()