


function get_task_details(todo_id){
  $('#modal_dialog').modal('show');
  $('.modal-text').empty(); $('#modal-footer').empty();
  $('.modal-text').append(`<div class='outer-div' id="modal-loader"><span class="inner-div spinner-border text-info align-self-center loader-sm"></span></div>`);
  $.getJSON(`/api/listTodoNotes/?todo_id=${todo_id}&format=json`, function(data) {
    $('.modal-text').empty(); $('#modal-footer').empty();
    note = data['notes'][0];
    subdomain_name = '';
    if (note['subdomain_name']) {
      subdomain_name = '<small class="text-success"> Subdomain: ' + note['subdomain_name'] + '</small></br>';
    }
    $('.modal-title').html(`<b>${htmlEncode(note['title'])}</b>`);
    $('#modal-content').append(`<p>${subdomain_name} ${htmlEncode(note['description'])}</p>`);
  });
}

function get_recon_notes(target_id, scan_id){
  var url = `/api/listTodoNotes/?`;

  if (target_id) {
    url += `target_id=${target_id}`;
  }
  else if (scan_id) {
    url += `scan_id=${scan_id}`;
  }

  url += `&format=json`;

  // <li class="list-group-item border-0 ps-0"><div class="form-check"><input type="checkbox" class="form-check-input todo-done" id="8"><label class="form-check-label" for="8">dd</label></div></li>
  $.getJSON(url, function(data) {
    $('#tasks-count').empty();
    $('#todo-list').empty();
    if (data['notes'].length > 0){
      $('#todo-list').append(`<li class="list-group-item border-0 ps-0" id="todo_list_${target_id}"></li>`);
      for (var val in data['notes']){
        note = data['notes'][val];
        div_id = 'todo_' + note['id'];
        subdomain_name = '';
        if (note['subdomain_name']) {
          subdomain_name = '<small class="text-success"> Subdomain: ' + note['subdomain_name'] + '</small></br>';
        }
        strike_tag = 'span';
        checked = '';
        if (note['is_done']) {
          strike_tag = 'del';
          checked = 'checked';
        }
        important_badge = '';
        mark_important = ''
        if (note['is_important']) {
          important_badge = `<i class="fe-alert-triangle text-danger me-1"></i>&nbsp;`;
          mark_important = `<a class="dropdown-item" onclick="change_todo_priority(${note['id']}, 0)">Mark UnImportant</a>`;
        }
        else{
          mark_important = `<a class="dropdown-item" onclick="change_todo_priority(${note['id']}, 1)">Mark Important</a>`;
        }
        $(`#todo_list_${target_id}`).append(`<div id="todo_parent_${note['id']}">
        <div class="d-flex align-items-start">
        <div class="w-100" onclick="get_task_details(${note['id']})">
        <input type="checkbox" class="me-1 form-check-input todo-done todo-item detail-scan-todo-item" ${checked} name="${div_id}" id="${div_id}">
        <label for="${div_id}" class="form-check-label">${important_badge}<${strike_tag}>${htmlEncode(note['title'])}</${strike_tag}></label>
        <${strike_tag}><p>${subdomain_name} <small>${truncate(htmlEncode(note['description']), 150)}</small></p></${strike_tag}>
        </div>
        <div class="btn-group dropstart float-end">
        <a href="#" class="text-dark dropdown-toggle float-start" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
        <i class="fe-more-vertical"></i>
        </a>
        <div class="dropdown-menu" style="">
        ${mark_important}
        <a class="dropdown-item" onclick="delete_todo(${note['id']})">Delete Todo</a>
        </div>
        </div>
        </div>
        <hr/>
        `);
      }
      $('#tasks-count').html(`<span class="badge badge-soft-primary">${data['notes'].length}</span>`);
    }
    else{
      $('#tasks-count').html(`<span class="badge badge-soft-primary me-1">0</span>`);
      $('#todo-list').append(`<p>No todos or notes...</br>You can add todo for individual subdomains or you can also add using + symbol above.</p>`);
    }
    $('.bs-tooltip').tooltip();
    todoCheckboxListener();
  });
}
