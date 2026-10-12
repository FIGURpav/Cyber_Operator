"""One read-only status view with distinct configuration and runtime boundaries."""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

if __package__:
    from . import (
        assessment_decisions,
        assessment_journal,
        configuration_report,
        report_contract,
        workspace_health,
        workspace_lifecycle,
    )
    from . import engagement_config as config
else:
    import assessment_decisions
    import assessment_journal
    import configuration_report
    import engagement_config as config
    import report_contract
    import workspace_health
    import workspace_lifecycle


def snapshot(root, *, report=False, now=None):
    root = Path(root).absolute()
    health = workspace_health.snapshot(root,now=now)
    result = {'schema_version':'1.0','runtime':health,'target_executor':False,'next_steps':[]}
    if not health['history_readable']:
        result['next_steps'] = [item['next_step'] for item in health['blockers']]
        return result
    state = config.status(root,now=now)
    result['configuration'] = state
    loaded = config.load(root)
    if loaded is None:
        result['next_steps'].append('Preview explicit configuration adoption before using managed commands.')
        return result
    draft = config.draft_state(root,loaded)
    result['questions'] = draft['missing']
    result['review_choices'] = {key:{'value':draft['definition'][key],'origin':draft['definition']['origins'][key]}
                                for key in ('excluded','maximum_impact','stop_conditions','artifact_handling','remote_storage',
                                            'remote_location','callback_cidrs','callback_ports','classification','retention_days','report_contract')}
    result['lifecycle'] = workspace_lifecycle.load_events(root)
    decisions = assessment_decisions.decision_states(root)
    result['decisions'] = {'journal_event_sequence':len(assessment_journal.load(root)),
                           'counts':dict(Counter(event['data']['status'] for event in decisions.values())),
                           'configuration_review_implies_activity_approval':False}
    manifest = report_contract.load_manifest(root)
    result['report'] = {'manifest_present':manifest is not None,'readiness':'not-evaluated'}
    if manifest and manifest['schema_version'] == '2.1':
        result['report']['configuration_snapshot_current'] = configuration_report.is_current(root,manifest)
    if report:
        if any(event['entity_kind']=='objective' for event in assessment_journal.load(root)):
            if __package__:
                from . import assessment_reporting
            else:
                import assessment_reporting
            readiness = assessment_reporting.readiness(root)
            result['report'].update(readiness='ready' if readiness['ready'] else 'incomplete',blockers=readiness['blockers'],contract='findings')
        else:
            readiness = report_contract.evaluate_contract(root)
            result['report'].update(readiness='ready' if not readiness.blockers else 'incomplete',blockers=list(readiness.blockers))
    if draft['missing']:
        result['next_steps'].append('Collect missing answers with cyber-engagement answer; review template defaults separately.')
    elif draft['event_sequence'] is not None:
        result['next_steps'].append('Review draft-show, then submit its complete configuration proposal.')
    elif state['status'] == 'ready-for-review':
        result['next_steps'].append('Show the complete configuration and record the configured reviewer decision.')
    if not manifest:
        result['next_steps'].append('Prepare report metadata after reviewing configuration and registering assets.')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--report',action='store_true',help='also evaluate full report readiness')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(snapshot(args.workspace,report=args.report),indent=2))
        return 0
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'error: {exc}',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
