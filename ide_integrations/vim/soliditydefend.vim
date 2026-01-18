" SolidityDefend Vim Plugin
" Advanced security analysis for Solidity smart contracts
" Maintainer: SolidityDefend Team
" License: MIT

if exists('g:loaded_soliditydefend')
    finish
endif
let g:loaded_soliditydefend = 1

" Plugin configuration
let g:soliditydefend_auto_analyze = get(g:, 'soliditydefend_auto_analyze', 1)
let g:soliditydefend_lsp_server = get(g:, 'soliditydefend_lsp_server', 'soliditydefend')
let g:soliditydefend_analysis_delay = get(g:, 'soliditydefend_analysis_delay', 2000)
let g:soliditydefend_show_signs = get(g:, 'soliditydefend_show_signs', 1)
let g:soliditydefend_show_highlights = get(g:, 'soliditydefend_show_highlights', 1)
let g:soliditydefend_dashboard_url = get(g:, 'soliditydefend_dashboard_url', 'http://localhost:8080')

" Initialize plugin
function! s:Init()
    " Define highlight groups
    call s:DefineHighlights()

    " Define signs
    call s:DefineSigns()

    " Set up autocommands
    call s:SetupAutocommands()

    " Create commands
    call s:CreateCommands()

    " Initialize variables
    let s:findings = {}
    let s:analysis_timer = -1
    let s:lsp_job = -1
endfunction

" Define syntax highlighting for security issues
function! s:DefineHighlights()
    if !g:soliditydefend_show_highlights
        return
    endif

    highlight default SolidityDefendCritical ctermfg=White ctermbg=Red guifg=White guibg=Red
    highlight default SolidityDefendHigh ctermfg=White ctermbg=DarkRed guifg=White guibg=DarkRed
    highlight default SolidityDefendMedium ctermfg=Black ctermbg=Yellow guifg=Black guibg=Yellow
    highlight default SolidityDefendLow ctermfg=Black ctermbg=LightGreen guifg=Black guibg=LightGreen
    highlight default SolidityDefendInfo ctermfg=Black ctermbg=LightBlue guifg=Black guibg=LightBlue
endfunction

" Define signs for the sign column
function! s:DefineSigns()
    if !g:soliditydefend_show_signs
        return
    endif

    sign define SolidityDefendCritical text=C texthl=SolidityDefendCritical
    sign define SolidityDefendHigh text=H texthl=SolidityDefendHigh
    sign define SolidityDefendMedium text=M texthl=SolidityDefendMedium
    sign define SolidityDefendLow text=L texthl=SolidityDefendLow
    sign define SolidityDefendInfo text=I texthl=SolidityDefendInfo
endfunction

" Set up autocommands for automatic analysis
function! s:SetupAutocommands()
    augroup SolidityDefend
        autocmd!
        if g:soliditydefend_auto_analyze
            autocmd BufWritePost *.sol call s:ScheduleAnalysis()
            autocmd TextChanged *.sol call s:ScheduleAnalysis()
            autocmd TextChangedI *.sol call s:ScheduleAnalysis()
        endif
        autocmd BufEnter *.sol call s:AnalyzeBuffer()
        autocmd BufLeave *.sol call s:ClearHighlights()
    augroup END
endfunction

" Create user commands
function! s:CreateCommands()
    command! SolidityDefendAnalyze call s:AnalyzeBuffer()
    command! SolidityDefendClear call s:ClearFindings()
    command! SolidityDefendShowFindings call s:ShowFindings()
    command! SolidityDefendQuickFix call s:ShowQuickFixes()
    command! SolidityDefendOpenDashboard call s:OpenDashboard()
    command! SolidityDefendToggleAutoAnalyze call s:ToggleAutoAnalyze()
    command! SolidityDefendExportReport call s:ExportReport()
endfunction

" Schedule analysis with debouncing
function! s:ScheduleAnalysis()
    if s:analysis_timer != -1
        call timer_stop(s:analysis_timer)
    endif

    let s:analysis_timer = timer_start(g:soliditydefend_analysis_delay, function('s:AnalyzeBuffer'))
endfunction

" Main analysis function
function! s:AnalyzeBuffer(...)
    if &filetype != 'solidity'
        return
    endif

    let s:analysis_timer = -1

    " Clear previous findings
    call s:ClearFindings()

    " Get buffer content
    let content = join(getline(1, '$'), "\n")
    let filename = expand('%:p')

    if empty(filename)
        let filename = 'buffer.sol'
    endif

    " Try LSP analysis first
    if s:IsLspAvailable()
        call s:AnalyzeWithLsp(content, filename)
    else
        " Fallback to pattern-based analysis
        call s:AnalyzeWithPatterns(content, filename)
    endif
endfunction

" Check if LSP server is available
function! s:IsLspAvailable()
    " Check if LSP server binary exists
    return executable(g:soliditydefend_lsp_server)
endfunction

" Analyze using LSP server
function! s:AnalyzeWithLsp(content, filename)
    " Create temporary file
    let temp_file = tempname() . '.sol'
    call writefile(split(a:content, "\n"), temp_file)

    " Build command
    let cmd = [g:soliditydefend_lsp_server, '--analyze', '--format', 'json', temp_file]

    " Run analysis asynchronously
    if has('nvim')
        let job_id = jobstart(cmd, {
            \ 'on_stdout': function('s:OnLspOutput'),
            \ 'on_stderr': function('s:OnLspError'),
            \ 'on_exit': function('s:OnLspExit'),
            \ 'stdout_buffered': 1,
            \ 'stderr_buffered': 1
        \ })
    else
        let job_id = job_start(cmd, {
            \ 'out_cb': function('s:OnLspOutput'),
            \ 'err_cb': function('s:OnLspError'),
            \ 'exit_cb': function('s:OnLspExit'),
            \ 'out_mode': 'raw',
            \ 'err_mode': 'raw'
        \ })
    endif

    let s:lsp_job = job_id
    let s:temp_file = temp_file
endfunction

" Handle LSP stdout
function! s:OnLspOutput(job_id, data, event)
    try
        let findings = json_decode(join(a:data, "\n"))
        call s:ProcessFindings(findings)
    catch
        echo "Failed to parse LSP output: " . v:exception
        " Fallback to pattern analysis
        let content = join(getline(1, '$'), "\n")
        call s:AnalyzeWithPatterns(content, expand('%:p'))
    endtry
endfunction

" Handle LSP stderr
function! s:OnLspError(job_id, data, event)
    echo "LSP Error: " . join(a:data, "\n")
endfunction

" Handle LSP exit
function! s:OnLspExit(job_id, exit_code, event)
    if exists('s:temp_file')
        call delete(s:temp_file)
        unlet s:temp_file
    endif

    if a:exit_code != 0
        echo "LSP analysis failed with code " . a:exit_code
        " Fallback to pattern analysis
        let content = join(getline(1, '$'), "\n")
        call s:AnalyzeWithPatterns(content, expand('%:p'))
    endif
endfunction

" Pattern-based analysis fallback
function! s:AnalyzeWithPatterns(content, filename)
    let findings = []
    let lines = split(a:content, "\n")

    for i in range(len(lines))
        let line = lines[i]
        let line_num = i + 1

        " Check for tx.origin usage
        let col = match(line, 'tx\.origin')
        if col != -1
            call add(findings, {
                \ 'id': 'tx_origin_' . line_num,
                \ 'detector': 'tx-origin',
                \ 'severity': 'Medium',
                \ 'title': 'Use of tx.origin',
                \ 'description': 'tx.origin should not be used for authorization',
                \ 'line': line_num,
                \ 'column': col + 1,
                \ 'suggested_fix': 'Replace tx.origin with msg.sender'
            \ })
        endif

        " Check for reentrancy patterns
        let col = match(line, '\.call(')
        if col != -1 && match(line, 'require(') == -1
            call add(findings, {
                \ 'id': 'reentrancy_' . line_num,
                \ 'detector': 'reentrancy',
                \ 'severity': 'High',
                \ 'title': 'Potential reentrancy vulnerability',
                \ 'description': 'External call without proper checks',
                \ 'line': line_num,
                \ 'column': col + 1,
                \ 'suggested_fix': 'Add reentrancy guard or check return value'
            \ })
        endif

        " Check for selfdestruct
        let col = max([match(line, 'selfdestruct'), match(line, 'suicide')])
        if col != -1
            call add(findings, {
                \ 'id': 'selfdestruct_' . line_num,
                \ 'detector': 'selfdestruct',
                \ 'severity': 'High',
                \ 'title': 'Use of selfdestruct',
                \ 'description': 'selfdestruct can be dangerous',
                \ 'line': line_num,
                \ 'column': col + 1,
                \ 'suggested_fix': 'Ensure proper access control'
            \ })
        endif

        " Check for missing access control
        if match(line, 'function\s\+\w\+.*public') != -1 && match(line, 'onlyOwner') == -1
            call add(findings, {
                \ 'id': 'access_control_' . line_num,
                \ 'detector': 'missing-access-control',
                \ 'severity': 'Medium',
                \ 'title': 'Missing access control',
                \ 'description': 'Public function may need access control',
                \ 'line': line_num,
                \ 'column': match(line, 'function') + 1,
                \ 'suggested_fix': 'Add access control modifier'
            \ })
        endif
    endfor

    call s:ProcessFindings(findings)
endfunction

" Process and display findings
function! s:ProcessFindings(findings)
    let s:findings[bufnr('%')] = a:findings

    " Display findings
    call s:ShowHighlights(a:findings)
    call s:ShowSigns(a:findings)
    call s:UpdateStatusLine(a:findings)

    " Show summary
    if len(a:findings) > 0
        echo printf("SolidityDefend: Found %d security issues", len(a:findings))
    else
        echo "SolidityDefend: No security issues found"
    endif
endfunction

" Show syntax highlighting for findings
function! s:ShowHighlights(findings)
    if !g:soliditydefend_show_highlights
        return
    endif

    " Clear previous matches
    call clearmatches()

    for finding in a:findings
        let line = finding.line
        let col = finding.column
        let severity = tolower(finding.severity)

        " Create match pattern
        let pattern = '\%' . line . 'l\%' . col . 'c.\{1,10}'

        " Add highlight
        let group = 'SolidityDefend' . toupper(severity[0]) . tolower(severity[1:])
        call matchadd(group, pattern)
    endfor
endfunction

" Show signs in the sign column
function! s:ShowSigns(findings)
    if !g:soliditydefend_show_signs
        return
    endif

    " Clear previous signs
    sign unplace * buffer=%

    for finding in a:findings
        let line = finding.line
        let severity = finding.severity
        let sign_name = 'SolidityDefend' . severity

        execute 'sign place ' . line . ' line=' . line . ' name=' . sign_name . ' buffer=' . bufnr('%')
    endfor
endfunction

" Update status line with findings count
function! s:UpdateStatusLine(findings)
    let critical = 0
    let high = 0
    let medium = 0
    let low = 0
    let info = 0

    for finding in a:findings
        let severity = tolower(finding.severity)
        if severity == 'critical'
            let critical += 1
        elseif severity == 'high'
            let high += 1
        elseif severity == 'medium'
            let medium += 1
        elseif severity == 'low'
            let low += 1
        else
            let info += 1
        endif
    endfor

    let status = printf("SD: %dC %dH %dM %dL %dI", critical, high, medium, low, info)
    let w:soliditydefend_status = status
endfunction

" Clear all findings and highlights
function! s:ClearFindings()
    call s:ClearHighlights()
    call s:ClearSigns()

    if exists('s:findings[' . bufnr('%') . ']')
        unlet s:findings[bufnr('%')]
    endif

    if exists('w:soliditydefend_status')
        unlet w:soliditydefend_status
    endif
endfunction

" Clear syntax highlighting
function! s:ClearHighlights()
    call clearmatches()
endfunction

" Clear signs
function! s:ClearSigns()
    sign unplace * buffer=%
endfunction

" Show findings in a quickfix window
function! s:ShowFindings()
    if !exists('s:findings[' . bufnr('%') . ']')
        echo "No findings available. Run :SolidityDefendAnalyze first."
        return
    endif

    let findings = s:findings[bufnr('%')]
    let qf_list = []

    for finding in findings
        call add(qf_list, {
            \ 'bufnr': bufnr('%'),
            \ 'lnum': finding.line,
            \ 'col': finding.column,
            \ 'text': '[' . finding.severity . '] ' . finding.title . ': ' . finding.description,
            \ 'type': s:SeverityToQfType(finding.severity)
        \ })
    endfor

    call setqflist(qf_list)
    copen
endfunction

" Convert severity to quickfix type
function! s:SeverityToQfType(severity)
    let severity = tolower(a:severity)
    if severity == 'critical' || severity == 'high'
        return 'E'
    elseif severity == 'medium'
        return 'W'
    else
        return 'I'
    endif
endfunction

" Show available quick fixes
function! s:ShowQuickFixes()
    if !exists('s:findings[' . bufnr('%') . ']')
        echo "No findings available."
        return
    endif

    let findings = s:findings[bufnr('%')]
    let line = line('.')
    let fixes = []

    " Find fixes for current line
    for finding in findings
        if finding.line == line && has_key(finding, 'suggested_fix')
            call add(fixes, finding)
        endif
    endfor

    if empty(fixes)
        echo "No quick fixes available for current line."
        return
    endif

    " Show fix options
    for i in range(len(fixes))
        echo (i + 1) . '. ' . fixes[i].suggested_fix
    endfor

    let choice = input("Select fix (1-" . len(fixes) . "): ")
    let idx = str2nr(choice) - 1

    if idx >= 0 && idx < len(fixes)
        call s:ApplyQuickFix(fixes[idx])
    endif
endfunction

" Apply a quick fix
function! s:ApplyQuickFix(finding)
    let detector = a:finding.detector

    if detector == 'tx-origin'
        call s:ReplaceTxOrigin()
    elseif detector == 'reentrancy'
        call s:AddReentrancyGuard()
    else
        echo "Quick fix not implemented for " . detector
    endif
endfunction

" Replace tx.origin with msg.sender
function! s:ReplaceTxOrigin()
    %s/tx\.origin/msg.sender/ge
    echo "Replaced tx.origin with msg.sender"
endfunction

" Add reentrancy guard (simplified)
function! s:AddReentrancyGuard()
    let line = line('.')
    let content = getline(line)

    " Simple approach: add nonReentrant modifier
    if match(content, 'function') != -1
        let new_content = substitute(content, '{', 'nonReentrant {', '')
        call setline(line, new_content)
        echo "Added nonReentrant modifier"
    else
        echo "Could not add reentrancy guard"
    endif
endfunction

" Open web dashboard
function! s:OpenDashboard()
    if executable('xdg-open')
        call system('xdg-open ' . g:soliditydefend_dashboard_url)
    elseif executable('open')
        call system('open ' . g:soliditydefend_dashboard_url)
    elseif has('win32')
        call system('start ' . g:soliditydefend_dashboard_url)
    else
        echo "Cannot open browser. Dashboard URL: " . g:soliditydefend_dashboard_url
    endif
endfunction

" Toggle auto-analyze
function! s:ToggleAutoAnalyze()
    let g:soliditydefend_auto_analyze = !g:soliditydefend_auto_analyze
    echo "Auto-analyze " . (g:soliditydefend_auto_analyze ? "enabled" : "disabled")
endfunction

" Export analysis report
function! s:ExportReport()
    if !exists('s:findings[' . bufnr('%') . ']')
        echo "No findings to export."
        return
    endif

    let findings = s:findings[bufnr('%')]
    let filename = input("Export to file: ", expand('%:r') . '_security_report.txt')

    if empty(filename)
        return
    endif

    let lines = []
    call add(lines, "SolidityDefend Security Analysis Report")
    call add(lines, "=====================================")
    call add(lines, "File: " . expand('%:p'))
    call add(lines, "Date: " . strftime("%Y-%m-%d %H:%M:%S"))
    call add(lines, "")
    call add(lines, "Summary:")
    call add(lines, "Total findings: " . len(findings))
    call add(lines, "")

    for i in range(len(findings))
        let finding = findings[i]
        call add(lines, (i + 1) . ". [" . finding.severity . "] " . finding.title)
        call add(lines, "   Location: Line " . finding.line . ", Column " . finding.column)
        call add(lines, "   Detector: " . finding.detector)
        call add(lines, "   Description: " . finding.description)
        if has_key(finding, 'suggested_fix')
            call add(lines, "   Suggested Fix: " . finding.suggested_fix)
        endif
        call add(lines, "")
    endfor

    call writefile(lines, filename)
    echo "Report exported to " . filename
endfunction

" Key mappings
function! s:SetupMappings()
    nnoremap <buffer> <LocalLeader>a :SolidityDefendAnalyze<CR>
    nnoremap <buffer> <LocalLeader>c :SolidityDefendClear<CR>
    nnoremap <buffer> <LocalLeader>f :SolidityDefendShowFindings<CR>
    nnoremap <buffer> <LocalLeader>q :SolidityDefendQuickFix<CR>
    nnoremap <buffer> <LocalLeader>d :SolidityDefendOpenDashboard<CR>
    nnoremap <buffer> <LocalLeader>e :SolidityDefendExportReport<CR>
endfunction

" Initialize the plugin
call s:Init()

" Set up mappings for Solidity files
autocmd FileType solidity call s:SetupMappings()

" Status line integration
function! SolidityDefendStatusLine()
    if exists('w:soliditydefend_status')
        return w:soliditydefend_status
    else
        return ''
    endif
endfunction