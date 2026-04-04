(function () {
    'use strict';

    var contract = window.UMHOperatorContract;
    var params = new URLSearchParams(window.location.search);
    var surfaceId = params.get('surface') === 'mobile' ? 'mobile' : 'desktop';
    var layout = contract.getSurfaceLayout(surfaceId);
    var operationId = layout.groups[0].operations[0];
    var lastPlan = null;

    document.body.classList.toggle('mobile', surfaceId === 'mobile');

    function byTestId(name) {
        return document.querySelector('[data-testid="' + name + '"]');
    }

    function create(tagName, className, text) {
        var element = document.createElement(tagName);
        if (className) { element.className = className; }
        if (text != null) { element.textContent = text; }
        return element;
    }

    function formatValue(value) {
        if (value == null) { return '(not applicable)'; }
        if (typeof value === 'string') { return value; }
        return JSON.stringify(value, null, 2);
    }

    function fieldValue(field) {
        var input = byTestId('field-' + field.name);
        if (input == null) { return null; }
        if (field.type === 'boolean') { return input.checked; }
        var raw = input.value.trim();
        if (raw.length === 0) { return null; }
        if (field.type === 'number') { return Number(raw); }
        if (field.type === 'json') { return JSON.parse(raw); }
        return raw;
    }

    function readInputs(operation) {
        var values = {};
        for (var i = 0; i < operation.fields.length; ++i) {
            var field = operation.fields[i];
            var value = fieldValue(field);
            if (value == null || value === false) { continue; }
            values[field.name] = value;
        }
        return values;
    }

    function setStatus(message, isError) {
        var node = byTestId('status-line');
        node.textContent = message;
        node.classList.toggle('is-error', !!isError);
    }

    function buildDescription(operation) {
        if (operation.controlOp != null) {
            return 'Dispatches canonical op "' + operation.controlOp + '" and preserves retained console semantics.';
        }
        if (operation.uiSnapshot === true) {
            return 'Renders the retained multi-section uiSnapshot envelope without changing raw console behavior.';
        }
        if (operation.serviceStatus === true) {
            return 'Renders lifecycle text output for "umhctl status --service".';
        }
        return 'Renders retained lifecycle text output.';
    }

    function renderDesktopNav() {
        var host = byTestId('desktop-nav');
        host.innerHTML = '';
        var heading = create('h2', null, 'Desktop Contract Map');
        host.appendChild(heading);
        for (var i = 0; i < layout.groups.length; ++i) {
            var group = layout.groups[i];
            var block = create('section', 'group');
            block.appendChild(create('div', 'group-label', group.label));
            for (var j = 0; j < group.operations.length; ++j) {
                var opId = group.operations[j];
                var button = create('button', 'op-button', opId);
                button.type = 'button';
                button.dataset.testid = 'desktop-op-' + opId;
                button.setAttribute('data-testid', 'desktop-op-' + opId);
                if (opId === operationId) { button.classList.add('is-active'); }
                button.addEventListener('click', function (event) {
                    operationId = event.currentTarget.textContent;
                    render();
                });
                block.appendChild(button);
            }
            host.appendChild(block);
        }
    }

    function renderMobileNav() {
        var host = byTestId('mobile-nav');
        host.innerHTML = '';
        var label = create('label', 'field', null);
        label.appendChild(create('span', null, 'Mobile operation selector'));
        var select = create('select', null, null);
        select.setAttribute('data-testid', 'mobile-operation-select');
        for (var i = 0; i < layout.groups.length; ++i) {
            var group = layout.groups[i];
            var optgroup = document.createElement('optgroup');
            optgroup.label = group.label;
            for (var j = 0; j < group.operations.length; ++j) {
                var option = create('option', null, group.operations[j]);
                option.value = group.operations[j];
                if (group.operations[j] === operationId) { option.selected = true; }
                optgroup.appendChild(option);
            }
            select.appendChild(optgroup);
        }
        select.addEventListener('change', function () {
            operationId = select.value;
            render();
        });
        label.appendChild(select);
        host.appendChild(label);
    }

    function renderForm(operation) {
        var host = byTestId('operation-form');
        host.innerHTML = '';
        for (var i = 0; i < operation.fields.length; ++i) {
            var field = operation.fields[i];
            var wrapper = create('label', 'field');
            wrapper.setAttribute('data-testid', 'field-wrap-' + field.name);
            wrapper.appendChild(create('span', null, field.flag));

            var input;
            if (field.type === 'select') {
                input = create('select');
                for (var j = 0; j < field.options.length; ++j) {
                    var option = create('option', null, field.options[j]);
                    option.value = field.options[j];
                    if (operation.sampleInput && operation.sampleInput[field.name] === field.options[j]) { option.selected = true; }
                    input.appendChild(option);
                }
            } else if (field.type === 'json') {
                input = create('textarea');
                input.value = JSON.stringify((operation.sampleInput && operation.sampleInput[field.name]) || {}, null, 2);
            } else if (field.type === 'boolean') {
                input = create('input');
                input.type = 'checkbox';
                input.checked = !!(operation.sampleInput && operation.sampleInput[field.name]);
            } else {
                input = create('input');
                input.type = (field.type === 'number') ? 'number' : 'text';
                if (operation.sampleInput && operation.sampleInput[field.name] != null) {
                    input.value = String(operation.sampleInput[field.name]);
                }
            }

            input.setAttribute('data-testid', 'field-' + field.name);
            wrapper.appendChild(input);
            wrapper.appendChild(create('div', 'field-note', field.required ? 'Required by the retained contract.' : 'Optional override in the retained contract.'));
            host.appendChild(wrapper);
        }
    }

    function renderPlan(plan) {
        byTestId('console-command').textContent = plan.consoleCommand || '(empty)';
        byTestId('control-request').textContent = formatValue(plan.controlRequest);
    }

    function renderResponse(operation, responseValue) {
        if (operation.renderMode === 'lifecycle-text') {
            byTestId('rendered-result').textContent = String(responseValue || '');
            return;
        }

        var payload = responseValue;
        if (typeof payload === 'string') {
            payload = JSON.parse(payload);
        }
        if (operation.renderMode === 'snapshot-json') {
            byTestId('rendered-result').textContent = 'umhctl uiSnapshot:\n' + JSON.stringify(payload, null, 2);
            return;
        }
        byTestId('rendered-result').textContent = 'umhctl response:\n' + JSON.stringify(payload, null, 2);
    }

    function buildPlan(operation) {
        var values = readInputs(operation);
        lastPlan = contract.buildDispatchPlan(operation.id, values);
        renderPlan(lastPlan);
        setStatus('Built ' + operation.id + ' for the ' + surfaceId + ' surface.', false);
        return lastPlan;
    }

    function render() {
        renderDesktopNav();
        renderMobileNav();

        var operation = contract.getOperation(operationId);
        var groupName = operation.category;
        byTestId('surface-label').textContent = layout.label;
        byTestId('operation-group').textContent = groupName;
        byTestId('render-mode').textContent = operation.renderMode;
        byTestId('operation-title').textContent = operation.id;
        byTestId('operation-description').textContent = buildDescription(operation);
        renderForm(operation);
        renderPlan({ consoleCommand: '', controlRequest: null });
        byTestId('dispatch-record').textContent = '';
        byTestId('rendered-result').textContent = '';
        byTestId('response-input').value = '';
        setStatus('Select an operation and build a retained dispatch plan.', false);

        byTestId('build-plan').onclick = function () {
            try {
                buildPlan(operation);
            } catch (error) {
                setStatus(error.message, true);
            }
        };

        byTestId('dispatch-plan').onclick = function () {
            try {
                var plan = buildPlan(operation);
                byTestId('dispatch-record').textContent = JSON.stringify({
                    surface: surfaceId,
                    dispatchedAtUtc: new Date().toISOString(),
                    operationId: plan.operationId,
                    consoleCommand: plan.consoleCommand,
                    controlRequest: plan.controlRequest
                }, null, 2);
            } catch (error) {
                setStatus(error.message, true);
            }
        };

        byTestId('sample-response').onclick = function () {
            byTestId('response-input').value = formatValue(operation.sampleResponse);
            setStatus('Loaded sample response for ' + operation.id + '.', false);
        };

        byTestId('render-response').onclick = function () {
            try {
                var raw = byTestId('response-input').value.trim();
                var responseValue = raw.length > 0 ? raw : operation.sampleResponse;
                renderResponse(operation, responseValue);
                setStatus('Rendered ' + operation.renderMode + ' output.', false);
            } catch (error) {
                setStatus(error.message, true);
            }
        };
    }

    render();
}());
