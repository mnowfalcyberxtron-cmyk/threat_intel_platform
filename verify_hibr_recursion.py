import asyncio
import json
from connectors.hibr import HIBRConnector
from engine.hibr_search import HIBRSecuritySearchEngine
from config import settings

async def main():
    hibr = HIBRConnector()
    engine = HIBRSecuritySearchEngine(hibr, max_depth=3)
    print('Starting investigation of basilicfly.com...')
    results = await engine.run('basilicfly.com', 'domain')
    
    print('\nInvestigation Complete!')
    print(f'API Calls Made: {results["stats"]["api_calls_made"]}')
    print(f'Entities Discovered: {results["stats"]["entities_discovered"]}')
    print(f'Metadata Records: {results["stats"]["metadata_count"]}')
    print(f'Fulldata Records: {results["stats"]["fulldata_count"]}')
    print(f'Stealer Records: {results["stats"]["fullstealer_count"]}')
    
    with open('output_basilicfly_test.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

if __name__ == '__main__':
    asyncio.run(main())
